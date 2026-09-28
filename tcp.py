import asyncio
import random
import time
from tcputils import *


# Piso para o TimeoutInterval. Evita retransmissões espúrias quando o SampleRTT
# medido é quase zero (ex.: rede local / testes). Coloque 0 para desativar.
TIMEOUT_MINIMO = 0.01


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # ================= PASSO 1: handshake (aceitar conexão) =================
            # O SYN+ACK é enviado dentro do construtor da Conexao.
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Segmento:
    """Segmento de dados enviado e ainda não confirmado (usado nos Passos 5 e 6)."""
    def __init__(self, seq_no, dados, tamanho, tempo_envio):
        self.seq_no = seq_no
        self.dados = dados            # segmento completo (cabeçalho + payload)
        self.tamanho = tamanho        # tamanho do payload
        self.tempo_envio = tempo_envio
        self.retransmitido = False


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # ---- estado do receptor (Passos 1, 2 e 4) ----
        self.ack_no = seq_no_cliente + 1          # próximo byte esperado do cliente

        # ---- estado do transmissor (Passos 3, 5, 6 e 7) ----
        self.seq_no = random.randint(0, 0xFFFF)   # número de sequência do nosso SYN
        self.fila_envio = []                      # pedaços (<= MSS) esperando janela
        self.nao_confirmados = []                 # segmentos enviados e sem ACK
        self.fin_enviado = False
        self.fechar_pendente = False
        self.fechando = False   # True assim que fechar() é chamado (Passo 4)

        # Passo 5: timer
        self.timer = None
        self.timeout_interval = 0.5               # valor constante até medir um SampleRTT

        # Passo 6: estimativa de RTT
        self.estimated_rtt = None
        self.dev_rtt = None

        # Passo 7: controle de congestionamento (AIMD), janela em bytes
        self.cwnd = MSS
        self.bytes_confirmados_na_janela = 0

        # ================= PASSO 1: responde o SYN com SYN+ACK =================
        self._enviar_segmento(self.seq_no, FLAGS_SYN | FLAGS_ACK)
        self.seq_no += 1                          # o SYN consome um número de sequência

    # ------------------------------------------------------------------
    # Utilitário: monta (com checksum) e envia um segmento para o cliente
    # ------------------------------------------------------------------
    def _enviar_segmento(self, seq_no, flags, payload=b''):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        header = make_header(dst_port, src_port, seq_no, self.ack_no, flags)
        segmento = fix_checksum(header + payload, dst_addr, src_addr)
        self.servidor.rede.enviar(segmento, src_addr)
        return segmento

    # ==================================================================
    # RECEPÇÃO
    # ==================================================================
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # ---- Passos 5, 6 e 7: trata ACKs recebidos ----
        if flags & FLAGS_ACK:
            self._processar_ack(ack_no)

        # ---- Passo 4: depois que fechar() foi chamado do nosso lado, não
        # processamos/entregamos mais nenhum dado que chegar do cliente ----
        if self.fechando:
            return

        # ---- Passo 2: só aceita segmentos em ordem (descarta duplicados/fora de ordem) ----
        if seq_no != self.ack_no:
            return

        tem_fin = bool(flags & FLAGS_FIN)
        if not payload and not tem_fin:
            return                                # ACK puro: nada a responder

        if payload:
            self.ack_no += len(payload)
        if tem_fin:
            self.ack_no += 1                      # o FIN consome um número de sequência

        # Confirma o que foi recebido corretamente (ACK com payload vazio)
        self._enviar_segmento(self.seq_no, FLAGS_ACK)

        if self.callback:
            if payload:
                self.callback(self, payload)      # Passo 2: entrega à camada de aplicação
            if tem_fin:
                self.callback(self, b'')          # Passo 4: sinaliza fechamento (b'')

    def registrar_recebedor(self, callback):
        self.callback = callback

    # ==================================================================
    # ENVIO
    # ==================================================================
    # ---- Passo 3: enviar (quebra em segmentos de até MSS) ----
    def enviar(self, dados):
        for i in range(0, len(dados), MSS):
            self.fila_envio.append(dados[i:i + MSS])
        self._enviar_pendentes()

    def _bytes_em_voo(self):
        return sum(s.tamanho for s in self.nao_confirmados)

    def _enviar_pendentes(self):
        # Passo 7: só envia enquanto couber na janela de congestionamento (cwnd)
        while self.fila_envio:
            payload = self.fila_envio[0]
            if self._bytes_em_voo() + len(payload) > self.cwnd:
                break
            self.fila_envio.pop(0)

            # Passo 3: monta o segmento com o número de sequência correto (flag ACK ligada)
            segmento = self._enviar_segmento(self.seq_no, FLAGS_ACK, payload)
            self.nao_confirmados.append(
                Segmento(self.seq_no, segmento, len(payload), time.time()))
            self.seq_no += len(payload)

            # Passo 5: inicia o timer ao enviar dados (se ele ainda não estiver rodando)
            if self.timer is None:
                self._iniciar_timer()

        # Passo 4: se o fechamento estava esperando a fila esvaziar, envia o FIN agora
        if self.fechar_pendente and not self.fila_envio:
            self.fechar_pendente = False
            self._enviar_fin()

    # ---- Passo 5: timer e retransmissão ----
    def _iniciar_timer(self):
        self._parar_timer()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        self.timer = loop.call_later(self.timeout_interval, self._timeout)

    def _parar_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        self.timer = None
        if not self.nao_confirmados:
            return

        # Passo 7: timeout -> reduz a janela pela metade (mínimo de 1 MSS)
        self.cwnd = max(MSS, self.cwnd // 2)
        self.bytes_confirmados_na_janela = 0

        # Passo 5: retransmite apenas o segmento mais antigo ainda não confirmado
        segmento = self.nao_confirmados[0]
        segmento.retransmitido = True             # Passo 6: não será usado como SampleRTT
        self.servidor.rede.enviar(segmento.dados, self.id_conexao[0])
        self._iniciar_timer()

    # ---- Passo 6: TimeoutInterval a partir do SampleRTT ----
    def _atualizar_rtt(self, sample_rtt):
        if self.estimated_rtt is None:
            # Primeira medição (RFC 2988)
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            alpha, beta = 0.125, 0.25
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
        self.timeout_interval = max(TIMEOUT_MINIMO, self.estimated_rtt + 4 * self.dev_rtt)

    # ---- Passos 5, 6 e 7: processamento de ACKs ----
    def _processar_ack(self, ack_no):
        confirmados = [s for s in self.nao_confirmados if s.seq_no + s.tamanho <= ack_no]
        if not confirmados:
            return
        self.nao_confirmados = [s for s in self.nao_confirmados if s not in confirmados]

        # Passo 6: SampleRTT apenas de segmento que NÃO foi retransmitido
        ultimo = confirmados[-1]
        if not ultimo.retransmitido:
            self._atualizar_rtt(time.time() - ultimo.tempo_envio)

        # Passo 7: ACK de uma janela inteira -> aumenta a janela em 1 MSS
        self.bytes_confirmados_na_janela += sum(s.tamanho for s in confirmados)
        if self.bytes_confirmados_na_janela >= self.cwnd:
            self.bytes_confirmados_na_janela -= self.cwnd
            self.cwnd += MSS

        # Passo 5: reinicia o timer se ainda há dados sem confirmação; senão, para
        self._parar_timer()
        if self.nao_confirmados:
            self._iniciar_timer()

        self._enviar_pendentes()

    # ==================================================================
    # FECHAMENTO
    # ==================================================================
    # ---- Passo 4: fechar (envia FIN) ----
    def fechar(self):
        if self.fin_enviado or self.fechar_pendente:
            return
        self.fechando = True
        if self.fila_envio:
            self.fechar_pendente = True           # espera os dados enfileirados saírem
        else:
            self._enviar_fin()

    def _enviar_fin(self):
        self.fin_enviado = True
        self._enviar_segmento(self.seq_no, FLAGS_FIN | FLAGS_ACK)
        self.seq_no += 1                          # o FIN consome um número de sequência

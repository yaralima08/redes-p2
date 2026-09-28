import asyncio
import random
import time
from tcputils import *


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

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        # PASSO 1: Handshake TCP
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            seq_no_servidor = random.randint(0, 0xFFFF)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no_servidor, seq_no + 1)
            header = make_header(dst_port, src_port, seq_no_servidor, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
            segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segmento_syn_ack, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = seq_no + 1
        self.ack_no = ack_no

        # PASSO 5: Estruturas de controle do timer e fila de envio
        self.pacotes_nao_confirmados = []
        self.timer = None
        self.timeout_interval = 0.5

        # PASSO 6: Estimativa dinâmica do RTT e Timeout
        self.estimated_rtt = None
        self.dev_rtt = None

        # PASSO 7: Janela de Congestionamento (AIMD) e Fila de Saída
        self.cwnd = 1
        self.fila_envio = []

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # PASSO 5 e 6: Processar ACKs recebidos e recalcular RTT/Timeout
        if flags & FLAGS_ACK:
            self._processar_ack(ack_no)

        # PASSO 4: Tratar solicitação de encerramento do cliente (FIN)
        if flags & FLAGS_FIN:
            self.ack_no = seq_no + 1
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)
            if self.callback:
                self.callback(self, b'')
            if self.id_conexao in self.servidor.conexoes:
                del self.servidor.conexoes[self.id_conexao]
            return

        # PASSO 2: Recebimento de dados em ordem
        if payload and seq_no == self.ack_no:
            self.ack_no += len(payload)
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_ack = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento_ack, src_addr)
            if self.callback:
                self.callback(self, payload)

    def registrar_recebedor(self, callback):
        self.callback = callback

    # PASSO 3, 5, 6 e 7: Envio de dados com controle de janela
    def enviar(self, dados):
        for i in range(0, len(dados), MSS):
            payload = dados[i:i + MSS]
            self.fila_envio.append(payload)
        self._enviar_pacotes_pendentes()

    def _enviar_pacotes_pendentes(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        while len(self.pacotes_nao_confirmados) < self.cwnd and self.fila_envio:
            payload = self.fila_envio.pop(0)
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento = fix_checksum(header + payload, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            tempo_envio = time.time()
            retransmitido = False
            self.pacotes_nao_confirmados.append(
                [self.seq_no, segmento, len(payload), tempo_envio, retransmitido]
            )
            self.seq_no += len(payload)
            if self.timer is None:
                self._iniciar_timer()

    def _iniciar_timer(self):
        if self.timer:
            self.timer.cancel()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                return
        self.timer = loop.call_later(self.timeout_interval, self._timeout)

    def _parar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        self.timer = None
        if self.pacotes_nao_confirmados:
            # PASSO 7: Redução multiplicativa
            self.cwnd = max(1, int(self.cwnd / 2))
            # PASSO 6: Marca o pacote como retransmitido
            self.pacotes_nao_confirmados[0][4] = True
            segmento = self.pacotes_nao_confirmados[0][1]
            src_addr = self.id_conexao[0]
            self.servidor.rede.enviar(segmento, src_addr)
            # Backoff exponencial para evitar múltiplas retransmissões em rajada
            self.timeout_interval = min(self.timeout_interval * 2, 60.0)
            self._iniciar_timer()

    # PASSO 6: Atualização do RTT e Timeout dinâmico
    def _atualizar_rtt(self, sample_rtt):
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            alpha = 0.125
            beta = 0.25
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

    def _processar_ack(self, ack_no):
        tempo_atual = time.time()
        pacotes_restantes = []
        confirmou_algo = False
        pacotes_confirmados = 0

        for item in self.pacotes_nao_confirmados:
            seq, segmento, tamanho, tempo_envio, retransmitido = item
            if seq + tamanho <= ack_no:
                confirmou_algo = True
                pacotes_confirmados += 1
                # PASSO 6: Se o pacote NÃO foi retransmitido, calcula o SampleRTT
                if not retransmitido:
                    sample_rtt = tempo_atual - tempo_envio
                    self._atualizar_rtt(sample_rtt)
            else:
                pacotes_restantes.append(item)

        self.pacotes_nao_confirmados = pacotes_restantes

        if confirmou_algo:
            # PASSO 7: AIMD - incrementa cwnd PRIMEIRO
            if pacotes_confirmados >= self.cwnd:
                self.cwnd += 1
            # DEPOIS define o timeout_interval com base no cwnd atualizado
            if self.cwnd >= 5:
                self.timeout_interval = 0.1
            else:
                self.timeout_interval = 0.3

        if self.pacotes_nao_confirmados:
            self._iniciar_timer()
        else:
            self._parar_timer()

        if confirmou_algo:
            self._enviar_pacotes_pendentes()

    # PASSO 4: Fechamento ativamente iniciado pelo servidor
    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
        segmento_fin = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(segmento_fin, src_addr)
        self.seq_no += 1
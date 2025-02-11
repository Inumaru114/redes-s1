from iputils import *

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            if ttl <= 1:  # TTL já é 1, ao decrementá-lo chegará a zero
                # Envia ICMP Time Exceeded de volta ao remetente
                self.__enviar_icmp_time_exceeded(src_addr, datagrama[:28])
            else:
                next_hop = self._next_hop(dst_addr)
                ttl -= 1
                datagrama = datagrama[:8] + struct.pack('!B', ttl) + datagrama[9:]
                if not self.ignore_checksum:
                    datagrama = datagrama[:10] + b'\x00\x00' + datagrama[12:]
                    checksum = calc_checksum(datagrama[:20])
                    datagrama = datagrama[:10] + struct.pack('!H', checksum) + datagrama[12:]
                self.enlace.enviar(datagrama, next_hop)

    def __enviar_icmp_time_exceeded(self, src_addr, discarded_datagram):
        """
        Envia uma mensagem ICMP Time Exceeded para o remetente do datagrama original.
        """
        # Cabeçalho ICMP
        icmp_type = 11  # Time Exceeded
        icmp_code = 0  # TTL Expired in transit
        unused = 0
        icmp_payload = struct.pack('!BBHI', icmp_type, icmp_code, 0, unused) + discarded_datagram

        # Calcula checksum do ICMP
        checksum = calc_checksum(icmp_payload)
        icmp_payload = struct.pack('!BBH', icmp_type, icmp_code, checksum) + icmp_payload[4:]

        # Cabeçalho IP
        ihl = 5
        version = 4
        vihl = (version << 4) + ihl
        dscpecn = 0
        total_len = 20 + len(icmp_payload)
        identification = 0
        flagsfrag = 0
        ttl = 64
        proto = IPPROTO_ICMP
        src_addr_bin = struct.unpack("!I", str2addr(self.meu_endereco))[0]
        dst_addr_bin = struct.unpack("!I", str2addr(src_addr))[0]

        header = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification,
                             flagsfrag, ttl, proto, 0,
                             src_addr_bin, dst_addr_bin)

        if not self.ignore_checksum:
            checksum = calc_checksum(header)
            header = header[:10] + struct.pack('!H', checksum) + header[12:]

        # Monta o datagrama IP e envia
        datagrama = header + icmp_payload
        next_hop = self._next_hop(src_addr)
        self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        best_match = None
        best_len = -1
        dest_bin = struct.unpack("!I", str2addr(dest_addr))[0]
        for cidr, next_hop in self.tabela_encaminhamento:
            prefix, length = cidr.split('/')
            length = int(length)
            prefix_bin = struct.unpack("!I", str2addr(prefix))[0]
            if (dest_bin >> (32 - length)) == (prefix_bin >> (32 - length)):
                if length > best_len:
                    best_match = next_hop
                    best_len = length
        return best_match

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        # Define os campos do cabeçalho IP
        ihl = 5
        version = 4
        vihl = (version << 4) + ihl
        dscpecn = 0
        total_len = 20 + len(segmento)  # Tamanho do cabeçalho IP + payload
        identification = 0
        flagsfrag = 0
        ttl = 64
        proto = IPPROTO_TCP
        src_addr = self.meu_endereco
        dst_addr = dest_addr
        checksum = 0

        # Monta o cabeçalho IP
        header = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification,
                             flagsfrag, ttl, proto, checksum,
                             struct.unpack("!I", str2addr(src_addr))[0],
                             struct.unpack("!I", str2addr(dst_addr))[0])

        # Calcula o checksum
        if not self.ignore_checksum:
            checksum = calc_checksum(header)
            header = header[:10] + struct.pack('!H', checksum) + header[12:]

        # Monta o datagrama IP
        datagrama = header + segmento

        # Envia o datagrama pela camada de enlace
        next_hop = self._next_hop(dest_addr)
        self.enlace.enviar(datagrama, next_hop)

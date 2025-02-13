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

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)
    
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

    def _next_hop(self, destino):
        destino_int = struct.unpack('!I', str2addr(destino))[0]
        melhor_prefixo = None
        maior_tamanho = -1
        
        for (cidr, salto) in self._rotas:
            rede, mascara = cidr.split('/')
            mascara = int(mascara)
            rede_int = struct.unpack('!I', str2addr(rede))[0]
            
            if (destino_int >> (32 - mascara)) == (rede_int >> (32 - mascara)):
                if mascara > maior_tamanho:
                    melhor_prefixo = salto
                    maior_tamanho = mascara
        
        return melhor_prefixo

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self._rotas = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def __enviar_icmp_time_exceeded(self, src_addr, discarded_datagram):
        tipo = 11
        codigo = 0
        cabecalho_icmp = struct.pack('!BBH', tipo, codigo, 0) + discarded_datagram
        checksum_icmp = calc_checksum(cabecalho_icmp)
        payload_icmp = struct.pack('!BBH', tipo, codigo, checksum_icmp) + cabecalho_icmp[4:]

        versao_ihl = 0x45
        dscpecn = 0
        comprimento_total = 20 + len(payload_icmp)
        cabecalho_ip = struct.pack('!BBHHHBBHII', 
            versao_ihl, dscpecn, comprimento_total,
            0, 0, 64, IPPROTO_ICMP, 0,
            struct.unpack('!I', str2addr(self.meu_endereco))[0],
            struct.unpack('!I', str2addr(src_addr))[0]
        )

        if not self.ignore_checksum:
            checksum = calc_checksum(cabecalho_ip)
            cabecalho_ip = cabecalho_ip[:10] + struct.pack('!H', checksum) + cabecalho_ip[12:]

        pacote = cabecalho_ip + payload_icmp
        self.enlace.enviar(pacote, self._next_hop(src_addr))

    def enviar(self, segmento, dest_addr):
        campos_cabecalho = (
            0x45, 0,  
            20 + len(segmento),  
            0,  
            0,  
            64, 
            IPPROTO_TCP,
            0,  
            struct.unpack('!I', str2addr(self.meu_endereco))[0],  
            struct.unpack('!I', str2addr(dest_addr))[0]  
        )

        cabecalho = struct.pack('!BBHHHBBHII', *campos_cabecalho)

        if not self.ignore_checksum:
            checksum = calc_checksum(cabecalho)
            cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]

        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, self._next_hop(dest_addr))

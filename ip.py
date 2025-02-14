import struct
import random
from iputils import calc_checksum, str2addr  # Certifique-se de ter uma função calc_checksum implementada em iputils.py
from iputils import read_ipv4_header  # Certifique-se de ter uma função de leitura de cabeçalho IPv4 em iputils.py

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
        self.endereco_host = None
        self.tabela_rotas = {}
        self.proximidade = -1
        self.identificador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identificacao, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.endereco_host:
            if proto == 6 and self.callback:  # 6 é o número de protocolo para TCP
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            self.proximidade = -1
            proximo_salto = self._next_hop(dst_addr)
            
            # Extrai campos do cabeçalho IP
            ver_ihl, dscpecn, comprimento, _, flg_offset, _, proto_num, head_chk, ip_src, ip_dst = struct.unpack('!BBHHHBBHII', datagrama[:20])
            campos_cabecalho = [ver_ihl, dscpecn, comprimento, self.identificador, flg_offset, ttl, proto_num, 0, ip_src, ip_dst]
            
            # Verifica e ajusta o campo TTL
            if ttl > 1:
                datagrama = self.montar_datagrama(payload, None, campos_cabecalho)
            else:
                proto_num = 1
                self.proximidade = -1
                proximo_salto = self._next_hop(src_addr)
                endereco_destino = proximo_salto
                if self.proximidade == 0:
                    endereco_destino = src_addr
                
                src_ip_int, = struct.unpack('!I', str2addr(self.endereco_host))
                dst_ip_int, = struct.unpack('!I', str2addr(endereco_destino))

                # Define o TTL para a resposta ICMP
                campos_cabecalho = [ver_ihl, dscpecn, comprimento, self.identificador, flg_offset, 64, proto_num, 0, src_ip_int, dst_ip_int]

                # Header ICMP Time Exceeded
                icmp_tipo = 0x0b
                icmp_codigo = 0
                icmp_checksum = 0
                icmp_unused = 0

                ihl = ver_ihl & 0xf
                icmp_tamanho = 4 * (ihl) + 8
                
                # Calcula checksum do ICMP
                cabecalho_icmp = struct.pack('!BBHI', icmp_tipo, icmp_codigo, icmp_checksum, icmp_unused) + (datagrama[:icmp_tamanho])
                icmp_checksum = calc_checksum(cabecalho_icmp)
                cabecalho_icmp = struct.pack('!BBHI', icmp_tipo, icmp_codigo, icmp_checksum, icmp_unused) + (datagrama[:icmp_tamanho])
                
                # Atualiza o tamanho do datagrama
                campos_cabecalho[2] = 20 + len(cabecalho_icmp)

                # Monta o datagrama final
                datagrama = self.montar_datagrama(cabecalho_icmp, None, campos_cabecalho)

                self.enlace.enviar(datagrama, proximo_salto)
                return

            self.enlace.enviar(datagrama, proximo_salto)

    def _next_hop(self, dest_addr):
        # Utiliza a tabela de encaminhamento para determinar o próximo salto
        int_dest, = struct.unpack('!I', str2addr(dest_addr))
        for cidr_val in self.tabela_rotas.keys():
            # Calcula o prefixo da sub-rede
            cidr, bits_ignorar = cidr_val.split('/')
            bits_ignorados = 32 - int(bits_ignorar)
            cidr_prefix, = struct.unpack('!I', str2addr(cidr))
            cidr_prefix = cidr_prefix >> bits_ignorados << bits_ignorados
            teste_prefixo = int_dest >> bits_ignorados << bits_ignorados

            if teste_prefixo == cidr_prefix:
                self.proximidade = int(bits_ignorar)
                return self.tabela_rotas[cidr_val]

    def definir_endereco_host(self, endereco_host):
        """
        Define o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços, atuaremos como roteador.
        """
        self.endereco_host = endereco_host

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        if len(self.tabela_rotas) > 0: 
            self.tabela_rotas.clear()

        tabela.sort(key=lambda rota: int(rota[0].split('/')[1]), reverse=True)

        for rota in tabela:
            self.tabela_rotas[rota[0]] = rota[1]

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
        self.proximidade = -1
        proximo_salto = self._next_hop(dest_addr)
        
        datagrama = self.montar_datagrama(segmento, dest_addr, [])

        self.enlace.enviar(datagrama, proximo_salto)

    def montar_datagrama(self, segmento, dest_addr, campos_cabecalho):
        """
        Monta o cabeçalho IP e o datagrama IP completo.
        """
        if len(campos_cabecalho) == 0:
            ver_ihl = 0x45
            dscpecn = 0x00
            comprimento = 20 + len(segmento)
            flg_offset = 0x00 
            ttl = 64  # Define o TTL como 64
            protocolo = 6
            header_checksum = 0
            identificador = self.identificador

            src_ip, = struct.unpack('!I', str2addr(self.endereco_host))
            dst_ip, = struct.unpack('!I', str2addr(dest_addr))

            self.identificador += comprimento
        else:
            ver_ihl, dscpecn, comprimento, identificador, flg_offset, ttl, protocolo, header_checksum, src_ip, dst_ip = campos_cabecalho
            ttl -= 1  # Decrementa o TTL

        # Certifique-se de que o TTL não fique abaixo de 1
        if ttl < 1:
            ttl = 1

        cabecalho_ip = struct.pack('!BBHHHBBHII', ver_ihl, dscpecn, comprimento, identificador, flg_offset, ttl, protocolo, header_checksum, src_ip, dst_ip)
        header_checksum = calc_checksum(cabecalho_ip)
        
        cabecalho_ip = struct.pack('!BBHHHBBHII', ver_ihl, dscpecn, comprimento, identificador, flg_offset, ttl, protocolo, header_checksum, src_ip, dst_ip)
        datagrama = cabecalho_ip + segmento

        return datagrama

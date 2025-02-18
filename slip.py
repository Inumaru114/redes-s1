class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.buffer = b''

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        datagrama_codificado = datagrama.replace(b'\xDB', b'\xDB\xDD')\
                                        .replace(b'\xC0', b'\xDB\xDC')
        datagrama_completo = b'\xC0' + datagrama_codificado + b'\xC0'
        self.linha_serial.enviar(datagrama_completo)

    def __raw_recv(self, dados):
        self.buffer += dados
        quadros = self.buffer.split(b'\xC0')
        self.buffer = quadros[-1]

        for quadro in quadros[:-1]:
            if quadro:
                try:
                    datagrama_decodificado = quadro.replace(b'\xDB\xDC', b'\xC0')\
                                                   .replace(b'\xDB\xDD', b'\xDB')
                    if self.callback:
                        self.callback(datagrama_decodificado)
                except Exception:
                    import traceback
                    traceback.print_exc()

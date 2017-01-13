# http server for dygraph visualization.
import sqlite3
import BaseHTTPServer


def hexdump(src, length=16):
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(
            ["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))

    res = ''.join(lines)
    res = res.replace('<', '&lt;')
    res = res.replace('>', '&gt;')
    res = res.replace('\n', '</br>')
    res += '</br>' * (2 - res.count('</br>'))
    return res


class CodemapHTTPServer(BaseHTTPServer.HTTPServer):
    def set_codemap(self, codemap):
        self.codemap = codemap


class CodemapHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def do_GET(self):
        page = self.path[1:]
        codemap = self.server.codemap
        
        # find the requested uid(r_uid) among current uid + prev_uids.
        r_uid = 'invalid_request'
        if page.find(codemap.uid) != -1:
            r_uid = codemap.uid
        else:
            for uid in codemap.prev_uids:
                if page.find(uid) != -1:
                    r_uid = uid
                    break

        if page.startswith(r_uid):
            if len(page.split('?')) > 1:
                params = page.split('?')[1].split('&')
                for p in params:
                    if p.startswith('sql='):
                        sql = p.split('sql=')[1]
                        # sql query is encoded with b64
                        codemap.query = sql.decode('base64')
                        codemap.query = codemap.query.lower()

                        # if query does not start with [select], consider as hex string search parameter.
                        if not codemap.query.startswith('select'):
                            tmpsql = ''
                            for i in range(0, len(codemap.arch.reg_list)): # skip ip register.
                                if i==0:
                                    tmpsql += 'select '+codemap.arch.reg_list[i]+' from trace'+r_uid+' where 2=1 '
                                    continue
                                tmpsql += "or m_{0} like '%{1}%' ".format(codemap.arch.reg_list[i], codemap.query.replace(' ',''))
                                
                            codemap.query = tmpsql

                        regs = codemap.query.split(
                            'select')[1].split('from')[0].split(',')
                        codemap.regs = '"id",'
                        for r in regs:
                            codemap.regs += '"{0}",'.format(r)
                        codemap.regs = codemap.regs[:-1]

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            skel = open(codemap.homedir + 'ui/skel.htm', 'rb').read()
            skel = skel.replace('--REPLACE--', codemap.uid)
            skel = skel.replace('--ARCH--', codemap.arch.name)    
            # if no baseaddr is configured then 0
            if codemap.base == 0:
                skel = skel.replace('--BASEADDR--', '0')
            else:
                skel = skel.replace(
                    '--BASEADDR--', hex(codemap.base).replace('0x', ''))
            skel = skel.replace(
                '--REGISTERS--', codemap.regs).replace('--SQL--', codemap.query)

            self.wfile.write( skel )

        # dynamically generate csv data set.
        elif page == 'data' + r_uid + '.csv':
            codemap.seq_dict[r_uid] = []
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            con = sqlite3.connect(codemap.homedir + "codemap.db")
            cur = con.cursor()

            sql = codemap.query.replace('select', 'select id,')
            cur.execute(sql)

            result = bytearray()
            seq = 1

            while True:
                r = cur.fetchone()
                if r is None:
                    break
                line = '{0},'.format(seq)
                for i in xrange(len(codemap.regs.split(','))):
                    if i == 0:
                        codemap.seq_dict[r_uid].append(r[i])
                        continue
                    line += '{0},'.format(r[i])

                result = result + line[:-1] + '\n'      # exception
                seq += 1
            self.wfile.write(str(result))
            con.close()

        elif page == 'dygraph-combined.jself.map':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write('')

        elif page == 'favicon.ico':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write('')

        elif page == 'dygraph.js':
            dygraph = open(codemap.homedir + 'ui/dygraph.js', 'rb').read()    
            self.send_response(200)
            self.send_header("Content-type", "text/javascript")
            self.end_headers()
            self.wfile.write(dygraph)

        elif page == 'interaction.js':
            interaction = open(codemap.homedir + 'ui/interaction.js', 'rb').read()    
            self.send_response(200)
            self.send_header("Content-type", "text/javascript")
            self.end_headers()
            self.wfile.write(interaction)

        elif page.startswith('mapx86.php?'):
            params = page.split('?')[1].split('&')
            base = 0
            guid = 0
            param = 0
            for p in params:
                if p.startswith('base='):
                    base = p.split('=')[1]
                if p.startswith('guid='):
                    guid = p.split('=')[1]
                if p.startswith('param='):
                    param = p.split('=')[1]

            # implement mapx86.php
            sql = "select * from trace{0} where id={1}".format(
                guid, codemap.seq_dict[guid][int(param) - 1])

            with codemap.thread_lock:
                con = sqlite3.connect(codemap.homedir + "codemap.db")
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute(sql)
                r = cur.fetchone()

                response = '''
                <html>
                <head>
                <style> td {{ font-family: 'Courier New', monospace; }} </style>
                </head>
                <body>
                <table border=1 cellspacing=0 cellpadding=0>
                <!--{eip}-->
                <tr><td><b>arg1[{arg1}]</b><br>{m_arg1}</td><td><b>arg2[{arg2}]</b><br>{m_arg2}</td></tr>
                <tr><td><b>arg3[{arg3}]</b><br>{m_arg3}</td><td><b>arg4[{arg4}]</b><br>{m_arg4}</td></tr>
                <tr><td><b>eax[{eax}]</b><br>{m_eax}</td><td><b>ebx[{ebx}]</b><br>{m_ebx}</td></tr>
                <tr><td><b>ecx[{ecx}]</b><br>{m_ecx}</td><td><b>edx[{edx}]</b><br>{m_edx}</td></tr>
                <tr><td><b>esi[{esi}]</b><br>{m_esi}</td><td><b>edi[{edi}]</b><br>{m_edi}</td></tr>
                <tr><td><b>ebp[{ebp}]</b><br>{m_ebp}</td><td><b>esp[{esp}]</b><br>{m_esp}</td></tr>
                </table>
                </body>
                </html>
                '''.format(
                    eip=hex(int(r['eip'])),
                    arg1=hex(int(r['arg1'])), m_arg1=hexdump(r['m_arg1'].decode('hex')), arg2=hex(int(r['arg2'])), m_arg2=hexdump(r['m_arg2'].decode('hex')),
                    arg3=hex(int(r['arg3'])), m_arg3=hexdump(r['m_arg3'].decode('hex')), arg4=hex(int(r['arg4'])), m_arg4=hexdump(r['m_arg4'].decode('hex')),
                    eax=hex(int(r['eax'])), m_eax=hexdump(r['m_eax'].decode('hex')), ebx=hex(int(r['ebx'])), m_ebx=hexdump(r['m_ebx'].decode('hex')),
                    ecx=hex(int(r['ecx'])), m_ecx=hexdump(r['m_ecx'].decode('hex')), edx=hex(int(r['edx'])), m_edx=hexdump(r['m_edx'].decode('hex')),
                    esi=hex(int(r['esi'])), m_esi=hexdump(r['m_esi'].decode('hex')), edi=hex(int(r['edi'])), m_edi=hexdump(r['m_edi'].decode('hex')),
                    ebp=hex(int(r['ebp'])), m_ebp=hexdump(r['m_ebp'].decode('hex')), esp=hex(int(r['esp'])), m_esp=hexdump(r['m_esp'].decode('hex'))
                )
                con.close()

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(response)

        elif page.startswith('mapx64.php?'):
            params = page.split('?')[1].split('&')
            base = 0
            guid = 0
            param = 0
            for p in params:
                if p.startswith('base='):
                    base = p.split('=')[1]
                if p.startswith('guid='):
                    guid = p.split('=')[1]
                if p.startswith('param='):
                    param = p.split('=')[1]
            # implement mapx64.php
            with codemap.thread_lock:
                con = sqlite3.connect(codemap.homedir + "codemap.db")
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                sql = "select * from trace{0} where id={1}".format(
                    guid, codemap.seq_dict[guid][int(param) - 1])
                cur.execute(sql)
                r = cur.fetchone()
                response = '''
                <html>
                <head>
                <style> td {{font-family: 'Courier New', monospace;}} </style>
                </head>
                <body>
                <table border=1 cellspacing=0 cellpadding=0>
                <!--{rip}-->
                <tr><td><b>rax[{rax}]</b><br>{m_rax}</td><td><b>rbx[{rbx}]</b><br>{m_rbx}</td></tr>
                <tr><td><b>rcx[{rcx}]</b><br>{m_rcx}</td><td><b>rdx[{rdx}]</b><br>{m_rdx}</td></tr>
                <tr><td><b>rsi[{rsi}]</b><br>{m_rsi}</td><td><b>rdi[{rdi}]</b><br>{m_rdi}</td></tr>
                <tr><td><b>rbp[{rbp}]</b><br>{m_rbp}</td><td><b>rsp[{rsp}]</b><br>{m_rsp}</td></tr>
                <tr><td><b>r8[{r8}]</b><br>{m_r8}</td><td><b>r9[{r9}]</b><br>{m_r9}</td></tr>
                <tr><td><b>r10[{r10}]</b><br>{m_r11}</td><td><b>r11[{r11}]</b><br>{m_r11}</td></tr>
                <tr><td><b>r12[{r12}]</b><br>{m_r12}</td><td><b>r13[{r13}]</b><br>{m_r13}</td></tr>
                <tr><td><b>r14[{r14}]</b><br>{m_r14}</td><td><b>r15[{r15}]</b><br>{m_r15}</td></tr>
                </table>
                </body>
                </html>
                '''.format(
                    rip=hex(int(r['rip'])),
                    rax=hex(int(r['rax'])), m_rax=hexdump(r['m_rax'].decode('hex')), rbx=hex(int(r['rbx'])), m_rbx=hexdump(r['m_rbx'].decode('hex')),
                    rcx=hex(int(r['rcx'])), m_rcx=hexdump(r['m_rcx'].decode('hex')), rdx=hex(int(r['rdx'])), m_rdx=hexdump(r['m_rdx'].decode('hex')),
                    rsi=hex(int(r['rsi'])), m_rsi=hexdump(r['m_rsi'].decode('hex')), rdi=hex(int(r['rdi'])), m_rdi=hexdump(r['m_rdi'].decode('hex')),
                    rbp=hex(int(r['rbp'])), m_rbp=hexdump(r['m_rbp'].decode('hex')), rsp=hex(int(r['rsp'])), m_rsp=hexdump(r['m_rsp'].decode('hex')),
                    r8=hex(int(r['r8'])), m_r8=hexdump(r['m_r8'].decode('hex')), r9=hex(int(r['r9'])), m_r9=hexdump(r['m_r9'].decode('hex')),
                    r10=hex(int(r['r10'])), m_r10=hexdump(r['m_r10'].decode('hex')), r11=hex(int(r['r11'])), m_r11=hexdump(r['m_r11'].decode('hex')),
                    r12=hex(int(r['r12'])), m_r12=hexdump(r['m_r12'].decode('hex')), r13=hex(int(r['r13'])), m_r13=hexdump(r['m_r13'].decode('hex')),
                    r14=hex(int(r['r14'])), m_r14=hexdump(r['m_r14'].decode('hex')), r15=hex(int(r['r15'])), m_r15=hexdump(r['m_r15'].decode('hex'))
                )
                con.close()

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(response)

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write('')
            print 'unknown page ', page

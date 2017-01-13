import os
import shutil
import platform

sysname = platform.system()
g_idadir = ''
g_homedir = ''

if sysname == 'Darwin' or sysname == 'Linux':
    g_idadir = '%s/.idapro' % os.environ['HOME']
    g_homedir = '%s/.idapro/codemap/' % os.environ['HOME']
elif sysname == 'Windows':
    g_idadir = '%s\\Hex-Rays\\IDA Pro\\' % os.environ['APPDATA']
    g_homedir = '%s\\Hex-Rays\\IDA Pro\\codemap\\' % os.environ['APPDATA']

if not os.path.exists(g_idadir):
    print 'IDA Pro is not installed!'
    os._exit(0)

if os.path.exists(g_homedir):
    print 'Codemap is already installed. Do you want to reinstall it? (y/n)'
    cmd = raw_input()
    if cmd is not 'y':
        os._exit(0)
    else:
        try:
            shutil.rmtree(g_homedir)
        except:
            print 'cannot remove existing files!! maybe Codemap files are locked by some application..'

if os.path.exists(g_idadir + 'idapythonrc.py'):
    print 'Codemap uses idapythonrc.py to place its code. it seems there already is idapythonrc.py'
    print 'Do you want to overwrite this? (y/n)'
    cmd = raw_input()
    if cmd is not 'y':
        os._exit(0)

shutil.copytree('codemap', g_homedir)
shutil.copy2('idapythonrc.py', g_idadir)

print 'Codemap install complete! run IDA Pro now.'

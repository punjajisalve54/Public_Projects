#!/bin/bash

while true; do
echo " "
echo " "
echo "Topic list for interview preparation"
echo "====================================

----------------------------
1.Linux Most IMP Skills
----------------------------
2.Virtualization Environment
----------------------------
3.Windows Environment
----------------------------
4.Common skills in win/linux
----------------------------
5.Cloud Technologies
----------------------------
6. Exit"


echo " "
echo " "
read -p "Select your topic from 1 to 5 ( or Press 6 to exit the script:) 🎯 " topic
echo " "
            
   case $topic in

	1) 

              while true; do
              clear
	      echo "i)   Linux Commands"
	      echo "ii)  Bash shell scripting"
	      echo "iii) Rhel vs Ubuntu "
	      echo "iv)  Rhel v7 VS v8 VS v9"
              echo "0)   Press zero to navigate to main menu"
              echo " "
              read -p "Select skill:🎯 " linux_skill
	      clear
              case $linux_skill in
			i)
                                while true; do 
            			echo " 3 different ways to study this skill"
				echo " ------------------------------------"
				echo " a) Interview Questions "
				echo " b) Scenario based questions "
				echo " c) Exam(quiz)"
				echo " 0) Back to the privious menu"
				       echo " "
				       read -p "Select your way of study: " linux_way
				       case $linux_way in
					       a)

clear
## Linux interview questions and answers
# Array of questions
linux_questions=(
'# Basic Linux Interview Questions

1. What is Linux?

Answer:

        Linux is an open-source, Unix-like operating system based on the Linux kernel. It is used for desktops, servers, and embedded systems.'
'2. What is the Linux kernel?

Answer:

       The Linux kernel is the core of the operating system that manages hardware, system processes, and memory.'
'3. What are the different types of Linux distributions?

Answer:

      Debian-based (Ubuntu, Kali Linux)
      RHEL-based (Red Hat, CentOS, Fedora)
      Arch-based (Arch Linux, Manjaro)
      SUSE-based (openSUSE, SLES)'
'4. How do you check the Linux kernel version?

Answer:

      uname -r'
'5. How do you check system uptime?

Answer:

      uptime'
'# File System & Directory Management

6. How do you list files and directories?

Answer:

       ls -l'
'7. How do you create and delete a directory?

Answer:

      Create: mkdir dirname
      Delete: rmdir dirname (empty directory) or rm -r dirname'
'8. How do you find a file in Linux?

Answer:

      find /path -name "filename"'
'9. How do you search for a string inside files?

Answer:

      grep "pattern" filename'
'10. What is the difference between ext3 and ext4?

Answer:

      Feature ext3    ext4
      Journaling      Yes     Yes
      Max File Size   16TB    1EB
      Performance     Slower  Faster'
'# User & Permission Management

11. How do you create a new user?

Answer:

      useradd -m username
      passwd username'
'12. How do you delete a user?

Answer:

      userdel -r username'
'13. How do you check the current logged-in users?

Answer:

     who
     w'
'14. How do you change file permissions in Linux?

Answer:

     chmod 755 filename'
'15. How do you change file ownership?

Answer:

      chown user:group filename'
'# Process Management

16. How do you check running processes?

Answer:

      ps aux'
'17. How do you find a specific process?

Answer:

      ps aux | grep process_name
18. How do you kill a process?

Answer:

      kill PID
      kill -9 PID'  # Force kill
'19. How do you check memory usage?

Answer:

      free -m'
'20. How do you check CPU usage?

Answer:

      top
      htop'  # Better alternative'
'# Networking Commands

21. How do you check your IP address?

Answer:

       ip a'
'22. How do you check network connectivity?

Answer:

      ping google.com'
'23. How do you check open ports?

Answer:

      netstat -tulnp
ss -tulnp'  # Faster alternative'
'24. How do you check system hostname?

Answer:

      hostname'
'25. How do you restart network services?

Answer:

      systemctl restart networking'
'# Disk Management

26. How do you check disk usage?

Answer:

      df -h'
'27. How do you check disk partitions?

Answer:

      fdisk -l
      lsblk'
'28. How do you format a partition?

Answer:

     mkfs.ext4 /dev/sdX'
'29. How do you mount a partition?

Answer:

      mount /dev/sdX /mnt'
'30. How do you unmount a partition?

Answer:

      umount /mnt'
'# Logging & Monitoring

31. How do you check system logs?

Answer:

      journalctl -xe'
'32. Where are system logs stored?

Answer:

    Logs are stored in /var/log/, such as:
    /var/log/syslog → System logs
    /var/log/auth.log → Authentication logs'
'33. How do you monitor real-time logs?

Answer:

      tail -f /var/log/syslog'
'34. How do you check failed login attempts?

Answer:

      cat /var/log/auth.log | grep "Failed password"'
'35. How do you check disk I/O usage?

Answer:

      iostat'
'# Package Management

36. How do you install a package in Ubuntu?

Answer:

      apt install package_name'
'37. How do you install a package in CentOS?

Answer:

      yum install package_name'
'38. How do you remove a package?

Answer:

     apt remove package_name  # Ubuntu
     yum remove package_name  # CentOS'
'39. How do you update all packages?

Answer:

      apt update && apt upgrade -y'
'40. How do you list installed packages?

Answer:

      dpkg -l  # Debian-based
      rpm -qa  # RHEL-based'
'# Shell Scripting & Automation

41. How do you write a simple Bash script?

Answer:

      #!/bin/
      echo "Hello, World!"'
'42. How do you make a script executable?

Answer:

      chmod +x script.sh
      ./script.sh'
'43. How do you run a script at startup?

Answer:

      Add it to /etc/rc.local or use systemd services.'
'44. How do you schedule a cron job?

Answer:

       crontab -e
       Example: Run script every 5 minutes
       */5 * * * * /path/to/script.sh'
'45. How do you find and replace text in a file?

Answer:

      sed -i "s/old_text/new_text/g" filename'
'#Advanced Linux Topics

46. How do you create a symbolic link?

Answer:

      ln -s target link_name'
'47. How do you set environment variables?

Answer:

       export VAR_NAME=value'
'48. What is nohup used for?

Answer:

       Keeps a command running even after logging out:
       nohup command &'
'49. How do you check SELinux status?

Answer:

      sestatus'
'50. How do you restart a service?

Answer:

     systemctl restart service_name'
)

## Linux Scenario based questions & answers

last_index=$(( ${#linux_questions[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${linux_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"
;;

b)
	 clear
## Scenario based linux interview questions and answers
# Array of questions
questions=(
'#1. System Performance & Troubleshooting (1-10)

 1. Scenario: A server is running slow. How do you diagnose the issue?

 Answer:

 Use top, htop, iostat, vmstat, and free -m to check CPU, RAM, disk, and swap usage.'
'2. Scenario: A process is consuming 100% CPU. How do you identify and stop it?

Answer:

 Use top or ps aux --sort=-%cpu, then kill it with kill -9 <PID>.'
'3. Scenario: Disk usage is 100%, but du and df show different results. Why?

Answer:

A deleted file still in use by a process may be consuming space. Find it using lsof | grep deleted.'
'4. Scenario: A server is running out of memory. How do you troubleshoot?

Answer:

 Use free -m, top, and ps aux --sort=-%mem to check RAM and swap usage.'
'5. Scenario: How do you check if a particular port is in use?

Answer:

 Use netstat -tulnp or ss -tulnp.'
'6. Scenario: Your server is rebooting randomly. How do you investigate?

Answer:

 Check logs in /var/log/messages or /var/log/syslog, and inspect dmesg for hardware issues.'
'7. Scenario: A user is unable to log in via SSH. How do you troubleshoot?

Answer:

Check /var/log/secure or /var/log/auth.log, ensure SSH service is running (systemctl status sshd), and verify firewall rules.'
'8. Scenario: A Linux server crashes. How do you analyze the cause?

Answer:

 Review /var/log/messages, dmesg, and /var/crash/.'
'9. Scenario: How do you check if a filesystem is mounted?

Answer:

 Use mount, df -h, or lsblk.'
'10. Scenario: You get a "Too many open files" error. How do you fix it?

Answer:

 Increase limits in /etc/security/limits.conf and use ulimit -n <value>.'
'# 2. File System & Disk Management (11-20)

11. Scenario: How do you extend a mounted LVM partition?

Answer:

 Use lvextend -L +10G /dev/mapper/vg-lv && resize2fs /dev/mapper/vg-lv.'
'12. Scenario: A disk is failing. How do you check its health?

Answer:

 Use smartctl -a /dev/sdX or badblocks.'
'13. Scenario: How do you find large files consuming disk space?

Answer:

 Use du -ah / | sort -rh | head -n 10.'
'14. Scenario: How do you add a new disk to a Linux server?

Answer:

 Partition with fdisk, format with mkfs.ext4, and mount it.'
'15. Scenario: How do you check disk I/O performance?

Answer:

 Use iostat, iotop, or dd if=/dev/zero of=test bs=64k count=16k conv=fdatasync.'
'16. Scenario: How do you create and mount a swap file?

Answer:

dd if=/dev/zero of=/swapfile bs=1G count=2
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile swap swap defaults 0 0" >> /etc/fstab'
'17. Scenario: How do you recover a deleted file?

Answer:

 Use extundelete (if on ext4) or check lsof for open file descriptors.'
'18. Scenario: How do you find which process is using a file?

Answer:

 Use lsof | grep <filename>.'
'19. Scenario: How do you fix a corrupted filesystem?

Answer:

 Run fsck -y /dev/sdX in rescue mode.'
'20. Scenario: How do you create a RAID 1 setup in Linux?

Answer:

Use mdadm:
mdadm --create --verbose /dev/md0 --level=1 --raid-devices=2 /dev/sdX /dev/sda1
mkfs.ext4 /dev/md0'
'#3. Networking (21-30)

21. Scenario: How do you check the current IP configuration?

Answer:

 Use ip a or ifconfig.'
'22. Scenario: A website is unreachable. How do you diagnose?

Answer:

 Use ping, traceroute, dig, and curl.'
'23. Scenario: How do you permanently assign an IP to a server?

Answer:

 Edit /etc/sysconfig/network-scripts/ifcfg-eth0 or /etc/netplan/.'
'24. Scenario: How do you check open ports on a server?

Answer:

 Use netstat -tulnp or ss -tulnp.'
'25. Scenario: How do you block an IP using the firewall?

Answer:

iptables -A INPUT -s <IP> -j DROP
firewall-cmd --permanent --add-rich-rule=rule family=ipv4 source address=IP reject'
'26. Scenario: How do you list all active network connections?

Answer:

 Use netstat -anp.'
'27. Scenario: How do you enable IP forwarding in Linux?

Answer:
echo "1" > /proc/sys/net/ipv4/ip_forward'
'28. Scenario: How do you configure DNS resolution in Linux?

Answer:

 Edit /etc/resolv.conf and set nameserver <IP>.'
'29. Scenario: How do you restart the network service?

Answer:

 Use systemctl restart network or service networking restart.'
'30. Scenario: How do you diagnose slow network speed?

Answer:

 Use iperf, ethtool, or mtr.'

'# 4. Security & User Management (31-40)

31. Scenario: A user forgot their password. How do you reset it?

Answer:

 Use passwd <username>.'
'32. Scenario: How do you lock and unlock a user account?

Answer:

usermod -L <username>  # Lock
usermod -U <username>  # Unlock'
'33. Scenario: How do you find failed login attempts?

Answer: Check /var/log/auth.log or /var/log/secure.'

'34. Scenario: How do you create a new sudo user?

Answer: Use usermod -aG sudo <username>.'

'35. Scenario: How do you check system security vulnerabilities?

Answer: Use lynis audit system.'

'# 5. Automation & Scripting (41-50)

36. How would you automate user creation in Linux using a script?
    Scenario: You need to create multiple users from a list in a file (users.txt).

Solution (Bash Script):
#!/bin/bash
while read user; do
    sudo useradd "$user" && echo "User $user created"
done < users.txt
Explanation:
Reads usernames from users.txt and creates users automatically.
&& ensures success messages only print if useradd is successful.'
'37. How can you automate file backups using a cron job?
Scenario: You need to back up /etc every day at midnight to /backup.

Solution:
Add this line to crontab -e:

0. 0 * * * tar -czf /backup/etc_backup_$(date +\%F).tar.gz /etc
Explanation:
Runs at 00:00 (midnight).
tar -czf compresses /etc and adds a timestamp to the filename.'
'38. How do you monitor disk space and send an alert if usage exceeds 90%?
Scenario: You need an automated disk space monitor.

Solution (Bash Script):

#!/bin/bash
THRESHOLD=90
df -h | awk NR>1 {if ($5+0 > 90) print $0} | while read line; do
    echo "Disk space alert: $line" | mail -s "Disk Alert" admin@example.com
done
Explanation:
Extracts disk usage (df -h).
If usage > 90%, sends an email alert.'
'39. How do you find and delete files older than 30 days automatically?
Scenario: You need to clean old logs from /var/logs.

Solution:
find /var/logs -type f -mtime +30 -exec rm -f {} \;
Explanation:
find locates files older than 30 days (-mtime +30).
-exec rm -f deletes them.'
'40. How do you automate SSH login using keys?
Scenario: You need to automate SSH login without a password.

Solution:
ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
ssh-copy-id user@remote-server
Explanation:
Generates an SSH key (ssh-keygen).
Copies the key to the remote server (ssh-copy-id).'
'41. How would you check if a process is running and restart if it’s not?
Scenario:
Ensure apache2 is always running.

Solution (Bash Script):
#!/bin/bash
if ! pgrep apache2 > /dev/null; then
    systemctl restart apache2
    echo "Apache restarted" | mail -s "Apache Restarted" admin@example.com
fi
Explanation:
Checks if apache2 is running (pgrep).
If not, restarts it and sends an email alert.'
'42. How can you automate software installation across multiple servers?
Scenario: You need to install nginx on multiple remote servers.

Solution (Using Ansible Playbook):
yaml

- hosts: webservers
  become: yes
  tasks:
    - name: Install nginx
      apt: name=nginx state=latest
Explanation:
Defines a playbook to install nginx on all webservers.'
'43. How do you schedule a script to run every Sunday at 3 AM?

Solution:

0. 3 * * 0 /path/to/script.sh

Explanation:
Runs at 03:00 AM every Sunday (0 is Sunday in crontab).'
'44. How do you check if a website is reachable using a script?

Solution (Bash Script):

#!/bin/bash
if ! curl -Is http://example.com | head -n 1 | grep "200 OK"; then
    echo "Website is down!" | mail -s "Website Alert" admin@example.com
fi
Explanation:

Uses curl to check HTTP status.
Sends an email if the site is down.'

'45. How do you automatically restart a service if it crashes?

Solution (Systemd Service File - /etc/systemd/system/myscript.service):

ini
[Service]
ExecStart=/usr/bin/myscript.sh
Restart=always
systemctl enable myscript.service
systemctl start myscript.service

Explanation:

Restart=always ensures automatic restart.'
'46. How do you extract the 5 most CPU-intensive processes?

Solution:

ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -6

Explanation:
Displays top 5 CPU-consuming processes (--sort=-%cpu).'
'47. How do you create a script to change file extensions in bulk?

Scenario: Rename .txt to .bak.

Solution:

for file in *.txt; do mv "$file" "${file%.txt}.bak"; done

Explanation:

Uses a loop to rename .txt to .bak.'
'48. How do you copy a large directory efficiently between servers?

Solution: rsync -avz /source/dir/ user@remote:/destination/dir/

Explanation:

Uses rsync for efficient syncing (-avz for compression & preservation).'
'49. How do you capture and analyze failed SSH login attempts?

Solution:

grep "Failed password" /var/log/auth.log | awk {print $11} | sort | uniq -c | sort -nr

Explanation:

Extracts failed logins from auth.log.
Displays IPs sorted by failure count.'
'50. How do you automate system updates with a script?

Solution (Bash Script):

#!/bin/bash
apt update && apt upgrade -y
echo "System updated on $(date)" >> /var/log/sys_update.log

Explanation:

Updates all packages (apt update && apt upgrade -y).
Logs the update timestamp.'


'51. Scenario: How do you schedule a cron job?

Answer: Use crontab -e and add 0 2 * * * /path/to/script.sh.'
'52. Scenario: How do you check cron job logs?

Answer: Check /var/log/cron.'

'53. Scenario: How do you automate user creation?

Answer: Use a bash script with useradd.'

'54. Scenario: How do you find and delete files older than 7 days?

Answer:

find /path -type f -mtime +7 -exec rm {} \;'

'55. Scenario: How do you create a basic shell script?

Answer:

#!/bin/bash
echo Hello, World!'

)

last_index=$(( ${#questions[@]} - 1 ))
Total_questions="55"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo ' Total 55 questions'
done
clear
echo "End of questions. Thanks for participating"
;;

c) 
	
QUESTIONS=(
"Which command is used to create a short name for a long command?|a) alias|b) shortcut|c) symlink|d) ln|a"
"What does the arch command do?|a) Displays system architecture (32-bit or 64-bit)|b) Prints CPU usage|c) Displays disk partition details|d) Shows the last login users|a"
"Which command is used to change directories in Linux?|a) mv|b) ls|c) cd|d) pwd|c"
"What does the pwd command do?|a) Displays the present working directory|b) Prints the user ID|c) Changes the working directory|d) Lists files in a directory|a"
"Which command is used to read a file?|a) ls|b) cat|c) rm|d) grep|b"
"The command to copy files or directories is:|a) cp|b) mv|c) copy|d) cut|a"
"Which command is used to remove a directory?|a) rmdir|b) rm -d|c) del|d) remove|a"
"Which command is used to create a new user?|a) useradd|b) adduser|c) newuser|d) createuser|a"
"The command to modify an existing user’s attributes is:|a) usermod|b) userchange|c) modifyuser|d) usermgmt|a"
"Which command is used to change a file’s owner?|a) chown|b) chmod|c) groupmod|d) ls -l|a"
"How do you display currently running processes?|a) ls|b) ps|c) run|d) proc|b"
"Which command is used to terminate a process using its process ID?|a) exit|b) end|c) kill|d) terminate|c"
"What does the nohup command do?|a) Runs a command in the background|b) Prevents a command from being interrupted after terminal exit|c) Starts a new user session|d) Restarts the system|b"
"Which command is used to check the connectivity between two machines?|a) ping|b) connect|c) nslookup|d) telnet|a"
"Which command is used for DNS lookup?|a) nslookup|b) hostname|c) ping|d) ifconfig|a"
"The command to display network interface details is:|a) ifconfig|b) ip|c) Both a & b|d) netstat|c"
"Which command is used to check disk space usage?|a) df|b) du|c) lsblk|d) fdisk|a"
"The command to check system memory usage is:|a) free|b) meminfo|c) top|d) iostat|a"
"How can you view real-time system resource usage?|a) top|b) uptime|c) loadavg|d) ps|a"
"Which command is used to read user input in a script?|a) read|b) input|c) echo|d) ask|a"
"Which command is used for running scheduled jobs?|a) cron|b) at|c) crontab|d) All of the above|d"
"Which of the following is a scripting loop command?|a) for|b) while|c) do|d) All of the above|d"
"What does the yum command do?|a) Install, update, or remove packages|b) Create a user account|c) Show system uptime|d) Check disk usage|a"
"Which command is used to create a local repository?|a) createrepo|b) mkrepo|c) localrepo|d) rpmrepo|a"
"What does the ls command do?|a) Lists files and directories|b) Deletes files|c) Moves files|d) Creates a new file|a"
"How do you change directories in Linux?|a) mv|b) cd|c) pwd|d) rm|b"
"Which command displays the current working directory?|a) pwd|b) ls|c) cd|d) whereis|a"
"What is the function of the mkdir command?|a) Delete a directory|b) Create a new directory|c) List all directories|d) Move a directory|b"
"How can you view the contents of a text file?|a) ls|b) cat|c) pwd|d) cd|b"
"How do you find the location of an installed command?|a) whereis|b) find|c) locate|d) search|a"
"Which command is used to find a specific string inside a file?|a) find|b) grep|c) locate|d) search|b"
"What does the chmod 755 filename command do?|a) Grants read, write, and execute permissions to the owner and read/execute to others|b) Changes the file owner|c) Deletes the file|d) Copies the file|a"
"How do you check system resource usage?|a) uptime|b) top|c) df|d) du|b"
"Which command is used to monitor real-time system logs?|a) tail -f /var/log/syslog|b) history|c) grep log|d) logview|a"
"What is the purpose of the iptables command?|a) Manage disk partitions|b) Configure network firewall rules|c) Monitor CPU usage|d) Display running processes|b"
"Which command is used to create a logical volume?|a) lvcreate|b) vgcreate|c) mkfs|d) fdisk|a"
"What does the cron command do?|a) Schedules recurring jobs|b) Runs a command once at a specific time|c) Creates a new user|d) Deletes files automatically|a"
"Which command is used to analyze disk space usage?|a) df|b) du|c) lsblk|d) fdisk|b"
"How can you restart a system service in Linux?|a) service restart|b) systemctl restart <service-name>|c) reboot|d) kill -9|b"
"Which command is used to move or rename a file?|a) mv|b) cp|c) rename|d) cut|a"
"What does the touch command do?|a) Opens a file|b) Deletes a file|c) Creates an empty file or updates the timestamp|d) Copies a file|c"
"The command to display the first few lines of a file is:|a) tail|b) head|c) less|d) cut|b"
"Which command is used to count words, lines, and characters in a file?|a) cut|b) wc|c) grep|d) awk|b"
"How can you delete a user account in Linux?|a) userdel|b) usermod -d|c) rmuser|d) deluser|a"
"Which command is used to change a user's password?|a) passwd|b) usermod -p|c) chpasswd|d) setpasswd|a"
"The command to add a new group is:|a) groupadd|b) addgroup|c) newgrp|d) creategroup|a"
"How do you bring a background process to the foreground?|a) bg|b) fg|c) jobs|d) resume|b"
"Which command is used to list all active processes?|a) ps|b) top|c) jobs|d) Both a & b|d"
"What is the function of the pkill command?|a) Kills a process using its PID|b) Kills all processes with a matching name|c) Starts a new process|d) Stops a system service|b"
"How do you check open ports and network connections?|a) netstat|b) ss|c) lsof|d) All of the above|d"
"The command used to test the reachability of a remote host is:|a) ping|b) telnet|c) nslookup|d) dig|a"
"How do you display the routing table of a system?|a) route|b) ip route show|c) netstat -r|d) All of the above|d"
"Which command is used to change file permissions?|a) chmod|b) chown|c) chgrp|d) setfacl|a"
"Which command is used to reboot a Linux system?|a) shutdown -r now|b) reboot|c) systemctl reboot|d) All of the above|d"
"How do you display the routing table of a system?|a) route|b) ip route show|c) netstat -r|d) All of the above|d"
"Which command is used to create a new partition?|a) fdisk|b) parted|c) mkfs|d) Both a & b|d"
"The command to check disk usage of directories is:|a) df|b) du|c) lsblk|d) fdisk|b"
"What does the mount command do?|a) Mounts a filesystem|b) Checks disk health|c) Creates a logical volume|d) Formats a partition|a"
"Which command is used to schedule repetitive tasks in Linux?|a) cron|b) at|c) crontab|d) All of the above|d"
"The read command in a script is used to:|a) Read user input|b) Display output|c) Write to a file|d) Run a script|a"
"What is the purpose of the sed command?|a) Sort text|b) Search and replace text|c) Extract text from a file|d) Display file content|b"
"What is the function of the firewall-cmd command?|a) Manage firewall rules in Linux|b) Display open ports|c) Enable or disable SELinux|d) None of the above|a"
"How do you switch to the root user temporarily?|a) sudo|b) su -|c) root|d) Both a & b|d"
"How do you check the system uptime?|a) uptime|b) top|c) loadavg|d) ps -e|a"
"What does the history command do?|a) Shows past executed commands|b) Displays last login users|c) Lists system logs|d) Clears command cache|a"
"How can you search for a command’s manual page?|a) man|b) help|c) info|d) All of the above|d"

        )

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Linux command MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "---------------------------------"

for i in "${!QUESTIONS[@]}"; do

    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo " "
    echo "-------------------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "-------------------------------"
    echo " "
    echo "Q$((i+1)). $QUESTION"

    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "
    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear

    fi
    echo "---------------------------------"
done
clear
echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "================================================"
echo "Keep practicing and mastering Linux commands! 🚀"
echo "------------------------------------------------"
echo " "
echo " "

;;

0) break ;;
*) echo "Invalid option try again." ;;

esac

done
;;

 ii) 
 while true; do
 echo " "
 echo " You selected bash skill"
 echo " " 
 echo " 3 different ways to study this skill"
 echo " ------------------------------------"
 echo " a) Interview Questions"
 echo " b) Scenario based questions"
 echo " c) Exam(quiz)"
 echo " 0) Back to the previous menu"
 echo " "
 read -p "Select your way of study: " bash_way
 case $bash_way in

 a)
# Store all questions in an array
questions=(
"1. What is Bash shell scripting?\n\nAnswer:\n\nBash shell scripting is a method of automating tasks in Unix/Linux by writing a sequence of commands in a script file that the Bash shell can execute."
"2. How do you create and execute a Bash script?\n\nAnswer:\n\nCreate a script file using a text editor, e.g., nano script.sh.\nWrite your script commands.\nSave and give execute permission: chmod +x script.sh.\nRun the script: ./script.sh."
"3. How do you define a variable in Bash?\n\nAnswer:\n\nUse VAR_NAME=value (without spaces around =). Example:\nname=\"John\"\necho \$name"
"4. How do you take user input in a Bash script?\n\nAnswer:\n\nUse the read command. Example:\necho \"Enter your name:\"\nread name\necho \"Hello, \$name!\""
"5. How do you use conditional statements in Bash?\n\nAnswer:\n\nUse if, elif, and else. Example:\nread -p \"Enter a number: \" num\nif [ \$num -gt 10 ]; then\n    echo \"Number is greater than 10\"\nelse\n    echo \"Number is 10 or less\"\nfi"
"6. How do you use a loop in Bash?\n\nAnswer:\n\nUse for, while, or until loops. Example:\nfor i in {1..5}; do echo \"Iteration \$i\"; done"
"7. How do you check if a file exists in Bash?\n\nAnswer:\n\nUse the -f option with an if statement. Example:\nif [ -f \"file.txt\" ]; then echo \"File exists\"; else echo \"File not found\"; fi"
"8. How do you check if a directory exists in Bash?\n\nAnswer:\n\nUse the -d option. Example:\nif [ -d \"mydir\" ]; then echo \"Directory exists\"; else echo \"Directory not found\"; fi"
"9. How do you append text to a file in Bash?\n\nAnswer:\n\nUse the >> operator. Example:\necho \"New line\" >> file.txt"
"10. How do you redirect standard output and error in Bash?\n\nAnswer:\n\nUse > for output and 2> for errors. Example:\ncommand > output.txt 2> error.txt"
"11. How do you execute a command stored in a variable?\n\nAnswer:\n\nUse eval or indirect expansion. Example:\ncmd=\"ls -l\"\neval \$cmd"
"12. How do you get the exit status of a command in Bash?\n\nAnswer:\n\nUse \$?. Example:\nls /nonexistent\necho \$?"
"13. How do you run a command in the background in Bash?\n\nAnswer:\n\nUse the & operator. Example:\nsleep 10 &"
"14. How do you kill a running process in Bash?\n\nAnswer:\n\nUse the kill command with the process ID (PID). Example:\nkill 1234"
"15. How do you create a function in Bash?\n\nAnswer:\n\nUse function keyword or define it like this:\nfunction my_func() { echo \"Hello\"; }\nmy_func"
"16. How do you pass arguments to a Bash script?\n\nAnswer:\n\nUse \$1, \$2, etc. Example:\n./script.sh arg1 arg2"
"17. How do you find the length of a string in Bash?\n\nAnswer:\n\nUse \${#var}. Example:\nstr=\"Hello\"\necho \${#str}"
"18. How do you extract a substring in Bash?\n\nAnswer:\n\nUse substring expansion. Example:\necho \${var:2:5}"
"19. How do you replace text in a string in Bash?\n\nAnswer:\n\nUse \${var/old/new}. Example:\nstr=\"Hello World\"\necho \${str/World/Bash}"
"20. How do you read a file line by line in Bash?\n\nAnswer:\n\nUse a while loop. Example:\nwhile read line; do echo \$line; done < file.txt"
"21. How do you get the current date in Bash?\n\nAnswer:\n\ndate command. Example:\ndate +\"%Y-%m-%d %H:%M:%S\""
"22. How do you sleep for a few seconds in Bash?\n\nAnswer:\n\nUse sleep. Example:\nsleep 5"
"23. How do you create an array in Bash?\n\nAnswer:\n\nUse parentheses. Example:\narr=(\"one\" \"two\" \"three\")"
"24. How do you loop through an array in Bash?\n\nAnswer:\n\nUse for loop. Example:\nfor i in \"\${arr[@]}\"; do echo \$i; done"
"25. How do you get the number of elements in an array?\n\nAnswer:\n\necho \${#arr[@]}"
"26. How do you check if a command exists in Bash?\n\nAnswer:\n\nUse command -v. Example:\ncommand -v ls"
"27. How do you check if a variable is empty in Bash?\n\nAnswer:\n\nUse -z. Example:\nif [ -z \"\$var\" ]; then echo \"Empty\"; fi"
"28. How do you make a script executable in Bash?\n\nAnswer:\n\nUse chmod +x. Example:\nchmod +x script.sh"
"29. How do you create a symbolic link in Bash?\n\nAnswer:\n\nUse ln -s. Example:\nln -s original.txt link.txt"
"30. How do you find the process ID (PID) of a running process?\n\nAnswer:\n\nUse pgrep. Example:\npgrep bash"
"31. How do you check memory usage in Bash?\n\nAnswer:\n\nUse free. Example:\nfree -h"
"32. How do you check disk usage in Bash?\n\nAnswer:\n\ndf -h"
"33. How do you print environment variables in Bash?\n\nAnswer:\n\nenv"
"34. How do you set an environment variable in Bash?\n\nAnswer:\n\nUse export. Example:\nexport VAR=value"
"35. How do you schedule a cron job in Bash?\n\nAnswer:\n\nUse crontab. Example:\ncrontab -e"
"36. How do you debug a Bash script?\n\nAnswer:\n\nUse set -x or bash -x script.sh"
"37. How do you find and replace text in a file in Bash?\n\nAnswer:\n\nUse sed. Example:\nsed -i 's/old/new/g' file.txt"
"38. How do you compare two files in Bash?\n\nAnswer:\n\ndiff file1.txt file2.txt"
"39. How do you compress a file in Bash?\n\nAnswer:\n\ntar -czf archive.tar.gz file.txt"
"40. How do you extract a compressed file in Bash?\n\nAnswer:\n\ntar -xzf archive.tar.gz"
)

# Loop through the questions
for question in "${questions[@]}"; do
    clear  # Clear the screen for better readability
    echo "Total questions:40"
    echo " "
    echo -e "$question"
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    read -p "Press Enter key to continue..."  # Wait for user input
done

echo "End of questions. Thanks for participating!"
;;

b) 
   ### Bash Scenario interview questionss
	clear

scenario_scripting=(
        '#. Basic Shell Scripting (1-10)

1 Scenario: How do you create and execute a basic Bash script?

✔ Answer:

echo "Hello, World!"
Save as script.sh, then run:
chmod +x script.sh
./script.sh'
'2 Scenario: How do you pass arguments to a shell script?

✔ Answer:

echo "First argument: $1"
echo "Second argument: $2"
Run as:
./script.sh arg1 arg2'
'3 Scenario: How do you check if a variable is empty?
✔
 Answer:

if [ -z "$VAR" ]; then
  echo "Variable is empty"
fi'
'4 Scenario: How do you make a script exit if an error occurs?
✔
 Answer:

set -e
This stops execution if any command fails.'
'5 Scenario: How do you store command output in a variable?

✔ Answer:

output=$(ls -l)
echo "$output"'
'6 Scenario: How do you read user input in a script?

✔ Answer:

read -p "Enter your name: " name
echo "Hello, $name!"'
'7 Scenario: How do you check if a file exists?

✔ Answer:

if [ -f "file.txt" ]; then
  echo "File exists"
fi'
'8 Scenario: How do you check if a directory exists?

✔ Answer:

if [ -d "/path/to/dir" ]; then
  echo "Directory exists"
fi'
'9 Scenario: How do you loop through a list of files in a directory?

✔ Answer:

for file in /path/to/dir/*; do
  echo "Processing $file"
done'
'10 Scenario: How do you schedule a script to run every day at midnight?

✔ Answer:

crontab -e
0 0 * * * /path/to/script.sh
2. String and Number Manipulation (11-20)'
'11 Scenario: How do you extract a substring from a string?

✔ Answer:

string="HelloWorld"
echo ${string:0:5}   # Output: Hello'

'12 Scenario: How do you replace a word in a string?

✔ Answer:

string="Hello World"
echo ${string/World/Shell}  # Output: Hello Shell'
'13 Scenario: How do you convert a string to uppercase?

✔ Answer:

 echo "hello" | tr [:lower:] [:upper:]'
'14 Scenario: How do you perform basic arithmetic in Bash?

✔ Answer:

echo $((5 + 3))'
'15 Scenario: How do you generate a random number in Bash?

✔ Answer:

echo $RANDOM'
'16 Scenario: How do you check if a number is even or odd?

✔ Answer:

if (( number % 2 == 0 )); then
  echo "Even"
else
  echo "Odd"
fi'
'17 Scenario: How do you check if a string contains a substring?

✔ Answer:

if [[ "hello world" == *"world"* ]]; then
  echo "Substring found"
fi'
'18 Scenario: How do you count the number of lines in a file?

✔ Answer:

wc -l file.txt'
'19 Scenario: How do you count the number of words in a string?

✔ Answer:

echo "Hello world" | wc -w'
'20 Scenario: How do you reverse a string in Bash?

✔ Answer:

echo "Hello" | rev'
'#3. File Handling (21-30)

21 Scenario: How do you create a file if it does not exist?

✔ Answer:

touch filename.txt'

'22 Scenario: How do you append text to a file?

✔ Answer:

echo "New line" >> file.txt'

'23 Scenario: How do you read a file line by line?

✔ Answer:

while IFS= read -r line; do
  echo "$line"
done < file.txt'
'24 Scenario: How do you delete a file?

✔ Answer:

rm filename.txt'
'25. Scenario: How do you copy a file

✔ Answer:

 cp file1.txt file2.txt'

'26 Scenario: How do you move a file?

✔ Answer:

mv file1.txt /new/location/'
'27 Scenario: How do you find and delete files older than 7 days?

✔ Answer:

find /path -type f -mtime +7 -exec rm {} \;'
'28 Scenario: How do you rename all .txt files to .bak in a directory?

✔ Answer:

for file in *.txt; do
  mv "$file" "${file%.txt}.bak"
done'
'29 Scenario: How do you list only directories?

✔ Answer:

ls -d */'
'30 Scenario: How do you compress and extract a .tar.gz file?

✔ Answer:

tar -czf archive.tar.gz file.txt
tar -xzf archive.tar.gz'

'# 4. Process Management (31-40)

31 Scenario: How do you find the process ID of a running program?

✔ Answer:

pgrep process_name'
'32 Scenario: How do you kill a process by name?

✔ Answer:

pkill process_name'
'33 Scenario: How do you run a process in the background?

✔ Answer:

command &
nohup command & disown'

'34 Scenario: How do you bring a background process to the foreground?

✔ Answer:

fg %job_number'
'35 Scenario: How do you check CPU usage of processes?

✔ Answer:

 top'
'36 Scenario: How do you limit CPU usage of a process?

✔ Answer:

cpulimit -p <PID> -l 50'
'37 Scenario: How do you restart a service?

✔ Answer:

systemctl restart service_name'
'38 Scenario: How do you list all running services?

✔ Answer:

systemctl list-units --type=service'
'39 Scenario: How do you check disk space usage?

✔ Answer:

df -h'
'40 Scenario: How do you monitor real-time logs of a service?

✔ Answer:

journalctl -fu service_name'
)

last_index=$(( ${#scenario_scripting[@]} - 1 ))


Total_questions="40"
echo " Total questions:$Total_questions"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_scripting[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 40 questions'
done
clear
echo " End of questions. Thanks for participating"
;;


c)
     
clear
	
QUESTIONS=(
    "What is Bash?|a) A programming language|b) A command-line interpreter|c) A database system|d) A cloud service|b"
    "Which symbol is used to define a variable in Bash?|a) $|b) @|c) %|d) #|a"
    "How do you make a script executable?|a) chmod +x script.sh|b) bash script.sh|c) run script.sh|d) exec script.sh|a"
    "Which command is used to print text to the terminal?|a) print|b) echo|c) output|d) display|b"
    "How do you take user input in Bash?|a) input|b) scan|c) read|d) get|c"
    "Which file is used to store user-specific Bash configurations?|a) /etc/bashrc|b) ~/.bashrc|c) ~/.profile|d) /bin/bash|b"
    "How do you check if a variable is empty?|a) if [ -z $var ]|b) if [ -n $var ]|c) if [ $var -eq 0 ]|d) if [ -s $var ]|a"
    "Which operator is used for string comparison in Bash?|a) -eq|b) ==|c) -gt|d) +=|b"
    "How do you create a function in Bash?|a) function myFunc {}|b) def myFunc {}|c) myFunc() {}|d) create myFunc {}|c"
    "Which loop is used to iterate over an array in Bash?|a) for|b) while|c) until|d) switch|a"
    "How do you append text to a file?|a) echo 'text' > file.txt|b) echo 'text' >> file.txt|c) write 'text' file.txt|d) append 'text' file.txt|b"
    "How do you check the exit status of the last command?|a) $?|b) $!|c) $?exit|d) exit $?|a"
    "Which command is used to display the first 10 lines of a file?|a) tail|b) head|c) cut|d) grep|b"
    "How do you run a script in debug mode?|a) bash -d script.sh|b) bash -x script.sh|c) bash --debug script.sh|d) bash debug script.sh|b"
    "Which command is used to replace text in a file?|a) sed|b) awk|c) grep|d) tr|a"
    "How do you find all files with a specific extension in a directory?|a) ls *.txt|b) find . -name '*.txt'|c) grep '*.txt'|d) locate '*.txt'|b"
    "Which command is used to schedule a cron job?|a) crontab -e|b) cron add|c) schedule -e|d) at -e|a"
    "How do you define an array in Bash?|a) array=(\"item1\" \"item2\")|b) array=[\"item1\", \"item2\"]|c) array={\"item1\", \"item2\"}|d) array: [\"item1\", \"item2\"]|a"
    "Which command is used to count lines, words, and characters in a file?|a) wc|b) count|c) grep -c|d) sum|a"
    "How do you exit a script with a specific exit code?|a) exit 1|b) return 1|c) quit 1|d) stop 1|a"
    "Which operator is used to check if two numbers are equal in Bash?|a) -eq|b) ==|c) =|d) -same|a"
    "How do you check if a file exists?|a) if [ -e filename ]|b) if [ -f filename ]|c) if exists filename|d) if file filename|a"
    "Which command is used to get the current working directory?|a) path|b) dir|c) pwd|d) ls|c"
    "How do you remove duplicate lines from a file?|a) sort -u file.txt|b) unique file.txt|c) dedup file.txt|d) awk '!seen[$0]++' file.txt|a"
    "Which command is used to replace a string in multiple files?|a) sed -i 's/old/new/g' *.txt|b) replace 'old' 'new' *.txt|c) grep -r 'old' *.txt|d) awk '{gsub(/old/, \"new\")}1' file.txt|a"
    "How do you run a command in the background?|a) command &|b) command &&|c) command background|d) run command|a"
    "Which Bash command is used to pause execution until a key is pressed?|a) wait|b) sleep|c) read -n 1|d) pause|c"
    "How do you rename a file in Bash?|a) rename old.txt new.txt|b) mv old.txt new.txt|c) rn old.txt new.txt|d) change old.txt new.txt|b"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Bash Scripting MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    QUESTION_TEXT="Q$((i+1)). $QUESTION"
    OPTIONS_TEXT="    $OPTION_A\n    $OPTION_B\n    $OPTION_C\n    $OPTION_D"

    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "$QUESTION_TEXT"
    echo -e "$OPTIONS_TEXT"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

    done
    clear
    echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
    echo "================================================"
    echo "Keep practicing and mastering Bash Scripting! 🚀"
    echo "------------------------------------------------"
    
    ;;

0) break ;;
*) echo "Invalid option. Try again." ;;

   esac

   done
   ;;

 iii)
while true; do
clear
echo " List of options"
echo " ---------------"
echo " "
echo " a) Key Differences Between Rhel & Ubuntu"
echo " 0) Press 0 to move back previous options"
echo " "
read -p " Press a for rhelv vs ubuntu ( or type 0 to go back):" rhel_way
case $rhel_way in

a)

# Array of tables
rhel_vs_ubuntu=(
 "@@ Key Differences Between RHEL & Ubuntu Commands @@

  Package Manager:
  RHEL uses YUM/DNF (yum install / dnf install)
  Ubuntu uses APT (apt install)
  Firewall:
  RHEL uses firewalld (firewall-cmd)
  Ubuntu uses UFW (ufw)
  Log Files:
  RHEL logs are in /var/log/messages
  Ubuntu logs are in /var/log/syslog
  User Management:
  RHEL uses useradd
  Ubuntu uses adduser"

"1. Check Linux Version

Task                    Red Hat (RHEL)                   Ubuntu
=======================================================================
Check OS version        cat /etc/redhat-release         lsb_release -a
-----------------------------------------------------------------------
Check kernel version    uname -r        uname -r
-----------------------------------------------------------------------
Check OS details        cat /etc/os-release     cat /etc/os-release
_______________________________________________________________________"

"2. Package Management

Task          Red Hat            (RHEL - yum/dnf/rpm)                      Ubuntu (apt/dpkg)
=================================================================================================================
Update package list----------->  yum/dnf update -y              apt update && apt upgrade -y

Install a package------------->  yum/dnf install <package>      apt install <package>

Installed package info ------->  yum/dnf info <package>         apt show <package>

Remove a package-------------->  yum/dnf remove <package>       apt remove <package>

To check Package history ----->  yum/dnf history                cat /var/log/apt/history.log

View package versions--------->  yum/dnf list --                apt list -a <package>
                                 showduplicates <package>  
------------------------------------------------------------------------------------------------------------------
Downgrade package  ----------->  yum/dnf history undo <id>      apt install <package_name>=<version_no>
                                                                apt-mark hold/unhold <package_name>
                                                                (To stop upgrading package or allowing)
Downgrade system update version> yum/dnf history undo <id>      Modifying source.list,apt pining,config
------------------------------------------------------------------------------------------------------------------
Remove a package-------------->  rpm -e <package>               dpkg -r <package>

List all installed packages--->  rpm -qa                        dpkg --list

Check package info------------>  rpm -qi <package>              dpkg -s package  or dpkg -l package

Install a local package------->  rpm -ivh <package>.rpm         dpkg -i <package>.deb

List all config file location->  rpm -qc <package>              dpkg -L openssh-server | grep /etc/

List all files location ------>  rpm -ql <package>              dpkg -L <package>

List command path of package-->  which <package_name>           which <package_name>

Command belongs to package---->  rpm -qf <command_path>         dpkg -S /path/to/file

To create local repository---->  creterepo_c <local_repo_path>  dpkg-scanpackages <local_repo_path>
------------------------------------------------------------------------------------------------------------------"


"3. User Management

Task                      Red Hat (RHEL)                                        Ubuntu
===========================================================================================================
Add a user--------------> useradd <username>                            adduser <username>
                          (Non Interactive or low-level)                (Interactive/High level cmd)i
-----------------------------------------------------------------------------------------------------------
Delete a user-----------> userdel <username>                            deluser <username>
Delete ~ & mail spool --> userdel -r <username>                         deluser --remove-home <username>
Remove user files    ---> find / -user <username> -exec rm -rf {} \;    deluser --remove-all-files username
------------------------------------------------------------------------------------------------------------
Modify a user-----------> usermod -aG <group> <username>                usermod -aG <group> <username>
Change ~ & mv files-----> usermod -d /new/home/path -m username         usermod -d /new/home/path -m username
Change default shell ---> usermod -s /bin/zsh username                  usermod -s /bin/sh username
Change password---------> passwd <username>                             passwd <username>
List groups-------------> cat /etc/group                                cat /etc/group
del user from grp>        gpasswd -d username <group>                   deluser username <group>
______________________________________________________________________________________"

"4. Service Management (Systemd)

Task                    Red Hat (RHEL)                        Ubuntu
======================================================================================
Start a service         systemctl start <service>       systemctl start <service>

Stop a service          systemctl stop <service>        systemctl stop <service>

Restart a service       systemctl restart <service>     systemctl restart <service>

Enable service at boot  systemctl enable <service>      systemctl enable <service>

Disable service at boot systemctl disable <service>     systemctl disable <service>

Check service status    systemctl status <service>      systemctl status <service>
______________________________________________________________________________________"

"5. Firewall Management

Task                       Red Hat (firewalld/iptables)             Ubuntu (ufw/iptables)
=========================================================================================
Check firewall status      systemctl status firewalld                   ufw status

Start firewall             systemctl start firewalld                    ufw enable

Stop firewall              systemctl stop firewalld                     ufw disable

Allow a port               firewall-cmd --add-port=80/tcp --permanent   ufw allow 80/tcp

Reload firewall rules      firewall-cmd --reload                        ufw reload
_________________________________________________________________________________________"

"6. Network Configuration

Task                       Red Hat (RHEL)          Ubuntu
=======================================================================
Show IP address            ip a or ifconfig        ip a or ifconfig

Check network interfaces   nmcli device status     ip link show

Show routing table         ip route                ip route

Ping a host                ping <host>             ping <host>
_______________________________________________________________________"

"7. Process Management

Task                     Red Hat (RHEL)    Ubuntu
===========================================================
List running processes   ps aux            ps aux

Kill a process           kill <PID>        kill <PID>

Find process by name     pgrep <name>      pgrep <name>

Monitor system usage     top or htop       top or htop
___________________________________________________________"

"8. Disk & Storage Management

Task                    Red Hat (RHEL)        Ubuntu
====================================================================
Check disk usage        df -h                 df -h

Check directory size    du -sh <dir>          du -sh <dir>

Show partition table    lsblk or fdisk -l     lsblk or fdisk -l

Mount a filesystem      mount /dev/sdX /mnt   mount /dev/sdX /mnt

Unmount a filesystem    umount /mnt           umount /mnt
_____________________________________________________________________"

"9. Log Management

Task                       Red Hat (RHEL)                  Ubuntu
================================================================================
Show system logs           journalctl -xe               journalctl -xe

View live logs             tail -f /var/log/messages    tail -f /var/log/syslog

View authentication logs   cat /var/log/secure          cat /var/log/auth.log
________________________________________________________________________________"

"10. Scheduled Jobs (Cron & Systemd Timers)

Task                   Red Hat (RHEL)           Ubuntu
=====================================================================
Edit cron jobs           crontab -e            crontab -e

List cron jobs           crontab -l            crontab -l

Systemd timers        systemctl list-timers    systemctl list-timers
(alternative to cron)
_____________________________________________________________________"

"11. Bonus: Virtualization & Containers

Task                  Red Hat (RHEL/KVM/Docker)     Ubuntu (KVM/Docker)
=============================================================================
List running VMs          virsh list --all          virsh list --all

Start a VM                virsh start <vm>          virsh start <vm>

Stop a VM                 virsh shutdown <vm>       virsh shutdown <vm>

List running containers   docker ps                 docker ps

Start a container         docker start <container>  docker start <container>
"

)

last_index=$(( ${#rhel_vs_ubuntu[@]} - 1 ))
Total_tables="11"
echo " Total comparison tables:$Total_tables"
# Loop through the tables one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${rhel_vs_ubuntu[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo "Total comparison tables 11"
done
clear
echo " End of comparison tables"
clear
;;

0) break ;;

*) echo "Invalid option try again." ;;

esac

done

;;

iv)

while true; do
clear

echo " List of options"
echo " ---------------"
echo " "
echo " a) Rhel version differences"
echo " 0) Press 0 to go back in previous menu"
echo " "
read -p " Select your choice: " rhel_ver
clear
case $rhel_ver in

a)

rhel_version_diff=(

"1. General Features
###################

Feature                    RHEL 7        RHEL 8         RHEL 9
===================================================================
Release Year               2014          2019           2023
-------------------------------------------------------------------
Kernel Version             3.10          4.18           5.x
-------------------------------------------------------------------
Default File System        XFS           XFS            XFS
-------------------------------------------------------------------
Maximum File System Size   50 TB (XFS)   1 PB (XFS)     1 PB (XFS)
-------------------------------------------------------------------
Boot Loader                GRUB2         GRUB2          GRUB2
-------------------------------------------------------------------
System Initialization      systemd       systemd (Improved) systemd
-------------------------------------------------------------------
"
"2. Package ManagemGent
######################

Feature                 RHEL 7             RHEL 8                RHEL 9
==========================================================================
Package Manager         YUM                DNF (Replaces YUM)    DNF
--------------------------------------------------------------------------
RPM Version             RPM 4.11           RPM 4.14              RPM 4.16
--------------------------------------------------------------------------
Application Streams     NA                 Yes                   Yes
                                          (Allows multiple
                                          versions of s/w)
---------------------------------------------------------------------------
Python Version       Python 2.x           Python 3.x(default)    Python 3.x
                 (Python 3 available)     python 2 removed

---------------------------------------------------------------------------
"
"3. Networking
#############

Feature            RHEL 7               RHEL 8                      RHEL 9
================================================================================
N/w Management    network-scripts       nmcli                       nmcli
                  & nmcli           (network-scripts removed)
--------------------------------------------------------------------------------
Firewall          firewalld            firewalld                   firewalld
                  (uses iptables)    (uses nftables)
--------------------------------------------------------------------------------
DNS Resolver      nsswitch.conf     systemd-resolved           systemd-resolved
--------------------------------------------------------------------------------
Bonding &         Bonding &        Bonding & Teaming         Bonding & Teaming
Teaming           Teaming
--------------------------------------------------------------------------------
"
"4. Security
###########

Feature              RHEL 7             RHEL 8             RHEL 9
=====================================================================
SELinux             Improved          Improved             Improved
---------------------------------------------------------------------
OpenSSL Version     OpenSSL 1.0.2   OpenSSL 1.1.1        OpenSSL 3.0
                                    (TLS 1.3 support)
---------------------------------------------------------------------
LUKS                LUKS v1           LUKS v2              LUKS V2
(Disk Encryption)                 (Stronger encryption)
---------------------------------------------------------------------
Root Password       Required          Optional             Optional
                                (Rootless setup available)
---------------------------------------------------------------------
System-wide
Cryptographic        NO                  Yes                     Yes
Policies
---------------------------------------------------------------------
"
"5. Process & System Management
###############################

Feature                RHEL 7                 RHEL 8
 RHEL 9
===========================================================================================
Process Management     systemd               systemd (More enhancements)    systemd
-------------------------------------------------------------------------------------------
Service Management    systemctl              systemctl
systemctl
-------------------------------------------------------------------------------------------
Logging System        rsyslog + journald     journald (Default)          journald (Default)
-------------------------------------------------------------------------------------------
Scheduler             CFS (Enhanced)              CFS
    CFS
                                           (Optimized for performance)     (Optimized)
--------------------------------------------------------------------------------------------
"
"6. Virtualization & Containers
###############################

Feature                RHEL 7        RHEL 8                     RHEL 9
=================================================================================================
Container Support      Docker       Podman, Buildah, Skopeo (Docker removed) Podman
-------------------------------------------------------------------------------------------------
KVM/QEMU               Supported    Supported                Supported (Optimized for performance)
-------------------------------------------------------------------------------------------------
Rootless Containers    No           Yes (Better security)     Yes
-------------------------------------------------------------------------------------------------
"
"7. Performance & Hardware Support
#################################

Feature                    RHEL 7              RHEL 8
    RHEL 9
==========================================================================================
Memory Support             Up to 3 TB      Up to 4.5 TB
 Up to 5 TB
------------------------------------------------------------------------------------------
CPU Support                Newer CPUs    Latest CPU architectures
 Latest CPUs
------------------------------------------------------------------------------------------
Power Management           Improved      Advanced power-saving features      Advanced
------------------------------------------------------------------------------------------
"
"8. Software & Deprecations
###########################

Feature                    RHEL 7         RHEL 8
RHEL 9
===========================================================================================
Default Web Server         Apache 2.4     Apache 2.4 (Updated modules)     Apache 2.4
-------------------------------------------------------------------------------------------
MySQL Version              MySQL 5.6      MySQL 8.0 (MariaDB as default)   MySQL 8.0
-------------------------------------------------------------------------------------------
Deprecated Features      Network-scripts  YUM, network-scripts             YUM, iptables
                           YUM, Docker    iptables removed                 iptables removed
-------------------------------------------------------------------------------------------
"
"Summary
#######

🚀 Key Improvements from RHEL 7 → RHEL 8
- YUM replaced by DNF (Faster package management)
- Podman replaces Docker (Rootless containers)
- nftables replaces iptables
- Application Streams introduced (Allows multiple versions of the same software)
- Python 3 is default, Python 2 removed
- LUKS v2 introduced (Better encryption security)

🚀 Key Improvements from RHEL 8 → RHEL 9
- Updated Kernel with improved security and performance
- OpenSSL 3.0 support
- Default logging system is journald
- Optimized CFS scheduler for better system performance
- System-wide cryptographic policies enhanced
"
)

last_index=$(( ${#rhel_version_diff[@]} - 1 ))
Total_tables="11"
echo " Rhel V7,v8,V9 comparison tables:$Total_tables"
# Loop through the tables one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${rhel_version_diff[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo " Total comparison tables 11"
        done
clear
echo "End of tables. Thanks for participating"
;;
0) break ;;
*) echo "Invalid option. Try again." ;;   
esac
done
;;
0) break ;;
*) echo "Invalid option. Try again.";;

esac

done

;;

2)

  while true; do
  echo " You selected virtualization topic"
  clear
  echo " "
  echo " List of virtualization skills"
  echo " ============================"
  echo "i)   Vmware Vsphere"
  echo "ii)  Microsoft hypervisor"
  echo "iii) Oracle Virtual Machine Manager"
  echo "iv)  Redhat Virtual Machine Manager"
  echo "0)   Back to the main menu"



                echo " "
                read -p 'Select skill:🎯 ' virtualization_skill 
                clear
                case $virtualization_skill in
                        i)
                                while true; do
				echo " You selected Vmware Vsphere virtualization skill"
                                echo " "
				echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"
                                echo " "
                                read -p "Select your way of study: " virtualization_way
                                case $virtualization_way in
   a) 
	 ## Place code here for
        clear
# Array of questions
vmware_vsphere_questions=(
'# VMware vSphere Interview Questions

1. What is VMware vSphere?

Answer:

        VMware vSphere is a server virtualization platform that includes ESXi hypervisor and vCenter Server for managing virtualized environments.'
'2. What are the main components of vSphere?

Answer:

        ESXi Hypervisor, vCenter Server, vSphere Client, vSphere Distributed Switch, vSAN, and vMotion.'
'3. What is ESXi?

Answer:

        ESXi is a type-1 hypervisor developed by VMware that allows multiple virtual machines to run on a single physical server.'
'4. What is vCenter Server?

Answer:

        vCenter Server is a centralized management platform for managing multiple ESXi hosts and virtual machines.'
'5. How do you install VMware ESXi?

Answer:

        Download ESXi ISO, create a bootable USB, boot the server from the USB, follow the installation steps, and configure networking and storage.'
'6. What is vMotion in VMware?

Answer:

        vMotion enables live migration of running virtual machines from one ESXi host to another without downtime.'
'7. What is HA (High Availability) in vSphere?

Answer:

        HA ensures high availability by restarting virtual machines on another host in case of a host failure.'
'8. What is DRS (Distributed Resource Scheduler)?

Answer:

        DRS automatically balances virtual machine workloads across multiple ESXi hosts based on CPU and memory utilization.'
'9. What is VMware vSAN?

Answer:

        vSAN is a software-defined storage solution that aggregates local storage devices across ESXi hosts to create a shared datastore.'
'10. What is a VMware Datastore?

Answer:

        A VMware Datastore is a storage container that holds virtual machine files, ISOs, and templates.'
'11. What are the different types of vSphere networking?

Answer:

        Standard vSwitch, Distributed vSwitch, and NSX networking.'
'12. How do you create a virtual machine in vSphere?

Answer:

        Use vSphere Client -> New Virtual Machine Wizard -> Configure settings -> Deploy.'
'13. What is a vSphere Cluster?

Answer:

        A vSphere Cluster groups multiple ESXi hosts to provide HA, DRS, and shared resources.'
'14. What is FT (Fault Tolerance) in VMware?

Answer:

        Fault Tolerance provides continuous availability by creating a secondary VM that mirrors the primary VM.'
'15. How do you take a snapshot of a VM?

Answer:

        Right-click VM -> Snapshots -> Take Snapshot -> Provide a name and description.'
'16. How do you restore a VM from a snapshot?

Answer:

        Right-click VM -> Snapshots -> Manage Snapshots -> Select snapshot -> Restore.'
'17. What is Linked Clone in VMware?

Answer:

        A Linked Clone is a VM that shares disk with a parent VM, reducing storage consumption.'
'18. What is a Template in VMware?

Answer:

        A Template is a master image of a virtual machine used for quick deployment of multiple identical VMs.'
'19. How do you add an ESXi host to vCenter?

Answer:

        Open vSphere Client -> Navigate to Hosts and Clusters -> Right-click Datacenter -> Add Host -> Enter host details.'
'20. How do you upgrade VMware Tools on a VM?

Answer:

        Right-click VM -> Guest -> Install/Upgrade VMware Tools -> Follow on-screen instructions.'
'21. What is Storage vMotion?

Answer:

        Storage vMotion allows live migration of VM disk files from one datastore to another without downtime.'
'22. What is VMKernel in VMware?

Answer:

        VMKernel is the core component of ESXi responsible for resource allocation and virtualization management.'
'23. How do you check the ESXi version?

Answer:

        Use vSphere Client -> Navigate to Host -> Summary tab or run vmware -v in ESXi shell.'
'24. What is a Host Profile in VMware?

Answer:

        A Host Profile captures configuration settings from an ESXi host to apply to other hosts for consistency.'
'25. What is a Resource Pool?

Answer:

        A Resource Pool allows administrators to allocate CPU and memory resources to VMs in a controlled manner.'
'26. What is vSphere Update Manager (VUM)?

Answer:

        VUM is a tool used to automate patching and upgrading of ESXi hosts and VMware tools.'
'27. How do you enable SSH on an ESXi host?

Answer:

        Go to Host -> Configure -> Services -> SSH -> Start Service.'
'28. What is the maximum number of hosts in a vSphere Cluster?

Answer:

        A vSphere Cluster can have up to 96 ESXi hosts (vSphere 7.x).'
'29. How do you check VM performance in vSphere?

Answer:

        Open vSphere Client -> Select VM -> Monitor -> Performance.'
'30. What is vApp in VMware?

Answer:

        vApp is a container for managing multiple VMs as a single unit with shared networking and policies.'
'31. How do you configure VM affinity rules?

Answer:

        Navigate to vSphere Client -> DRS Rules -> Create VM Affinity Rule.'
'32. What is the purpose of vSphere Tags?

Answer:

        vSphere Tags help categorize and organize virtual machines and other resources for better management.'
'33. What is a Content Library in vSphere?

Answer:

        A Content Library stores VM templates, ISOs, and scripts for easy sharing across vCenter Servers.'
'34. How do you back up vCenter Server?

Answer:

        Use vCenter Server Appliance Management Interface (VAMI) or third-party backup solutions.'
'35. What is the purpose of VMware Tools?

Answer:

        VMware Tools enhances VM performance, enables guest OS interaction, and provides advanced features like time synchronization.'
'36. How do you configure a vSwitch in vSphere?

Answer:

        Navigate to Networking -> vSwitches -> Add/Modify vSwitch settings.'
'37. What is a VMX file in VMware?

Answer:

        A VMX file contains configuration details of a virtual machine.'
'38. How do you enable EVC (Enhanced vMotion Compatibility)?

Answer:

        Edit vSphere Cluster settings -> Enable EVC -> Select CPU Mode.'
'39. What is the role of NSX in VMware?

Answer:

        NSX is VMware’s network virtualization and security platform that enables micro-segmentation and software-defined networking.'
'40. How do you check vSAN health status?

Answer:

        Go to vSphere Client -> vSAN Cluster -> Monitor -> vSAN Health.'
)

last_index=$(( ${#vmware_vsphere_questions[@]} - 1 ))
Total_questions="${#vmware_vsphere_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${vmware_vsphere_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"



	;;

  b)


clear

scenario_vmware=(
'#Basic vSphere Scenarios (1-10)


1 Scenario: You are asked to deploy a new virtual machine. What are the key considerations?

✔ Answer:

 Ensure sufficient resources (CPU, RAM, storage), select the correct VM compatibility, configure networking,
and choose the appropriate storage (vSAN, NFS, VMFS).'

'2 Scenario: A VM is running slow. How would you troubleshoot?

✔ Answer:

 Check CPU/Memory usage in vSphere Client, verify storage latency, check network performance, and examine ESXi host resource utilization.'

'3 Scenario: A VM is not powering on. What could be the reasons?

✔ Answer:

 Check for resource constraints, snapshot dependencies, locked VM files, corrupted VMDK, or misconfigured VM settings.'

'4 Scenario: You need to migrate a running VM to another host without downtime. What method do you use?

✔ Answer:

Use vMotion for live migration of VMs between ESXi hosts.'


'5 Scenario: How do you ensure a VM can survive an ESXi host failure?

✔ Answer:

  Configure vSphere High Availability (HA) to automatically restart VMs on other hosts in case of failure.'

'6 Scenario: A VM’s storage is running out of space. How do you increase disk size?

✔ Answer:

 Expand the VMDK via vSphere Client, then extend the partition inside the guest OS.'

'7 Scenario: Your company needs automatic VM provisioning. What feature can help?

✔ Answer:

 Use vSphere Auto Deploy or vRealize Automation for automated provisioning.'

'8 Scenario: How do you back up a VMware VM?

✔ Answer:

 Use VMware vSphere Data Protection (VDP), Veeam Backup, or Snapshots for backups.'

'9 Scenario: What happens when a VM reaches 100% CPU usage?

✔ Answer:

 The VM may experience performance issues; check ESXi host CPU usage and enable CPU Shares or Resource Pools.'

'10 Scenario: How do you limit CPU and RAM for a VM?

✔ Answer:

 Use Resource Allocation Settings in vSphere Client to set CPU/RAM limits and reservations.'

'# Networking & Storage Scenarios (11-20)

11 Scenario: A VM has lost network connectivity. How do you troubleshoot?

✔ Answer:

 Check the VM’s vNIC, verify vSwitch and port group settings, confirm VLAN configuration, and check physical networking.'

'12 Scenario: How do you configure network redundancy in VMware?

✔ Answer:

 Use NIC Teaming and configure multiple uplinks in vSwitch settings.'

'13 Scenario: A host can’t connect to shared storage. What do you check?

✔ Answer:

Verify iSCSI/NFS configuration, check storage LUN permissions, restart the storage service, and check network connectivity.'

'14 Scenario: How do you reduce storage usage in VMware?

✔ Answer:

Use Thin Provisioning, Storage DRS, and deduplication/compression in vSAN.'

'15 Scenario: How do you migrate a VM’s storage to another datastore?

✔ Answer:

 Use Storage vMotion to move VMDKs without downtime.'

'16 Scenario: What’s the difference between VMFS and NFS storage?

✔ Answer:

 VMFS is block storage; NFS is file-based. VMFS supports vMotion and snapshots, while NFS is more flexible for shared access.'

'17 Scenario: A VM cannot access shared storage. What do you check?

✔ Answer:

 Check the datastore mounting status, verify iSCSI/NFS connectivity, and confirm permissions on the storage side.'

'18 Scenario: What’s the benefit of vSAN over traditional storage?
✔ Answer:

 vSAN is software-defined storage that aggregates local disks, reducing dependency on external SAN/NAS solutions.'

'19 Scenario: You need to isolate network traffic between VMs. What feature can help?

✔ Answer:

Use VLANs, Private VLANs, or vSphere Distributed Switches.'

'20 Scenario: How do you ensure high availability for vSphere networking?

✔ Answer:

 Use vSphere Distributed Switches (vDS) and configure redundant uplinks.'

'# High Availability & Fault Tolerance Scenarios (21-30)

21 Scenario: An ESXi host crashes. What happens to its VMs?

✔ Answer:

 If vSphere HA is enabled, VMs restart on another host.'

'22 Scenario: How do you prevent VM downtime if a host fails?

✔ Answer:

Use Fault Tolerance (FT) to maintain an active secondary VM that takes over instantly.'

'23 Scenario: A VM failed over using HA but is performing slowly. Why?

✔ Answer:

 The new host might have fewer resources, leading to performance degradation.'

'24 Scenario: How do you ensure a critical VM always gets priority resources?

✔ Answer:

Use Resource Pools and set high CPU/memory reservations.'

'25 Scenario: What’s the difference between vSphere HA and Fault Tolerance?

✔ Answer:

 HA restarts VMs on another host, while FT provides continuous availability with a secondary VM.'


'26 Scenario: How do you test vSphere HA functionality?

✔ Answer:

 Simulate a host failure by powering off a host or disconnecting it from the network.'

'27 Scenario: A host is frequently failing. How do you investigate?ate

✔ Answer:

 Check hardware logs, verify power supply, update firmware, and check storage/network issues.'

'28 Scenario: What happens if vCenter goes down?

✔ Answer:

Running VMs remain unaffected, but management tasks (e.g., vMotion, DRS) are unavailable.'

'29 Scenario: A cluster has HA enabled, but VMs are not restarting. What could be wrong?

✔ Answer:

 Check cluster settings, host isolation response, and admission control policies.'

'30 Scenario: How do you avoid resource contention in an HA cluster?

✔ Answer:

 Configure Admission Control to reserve spare capacity for failover.'

'#Advanced vSphere Scenarios (31-50)
31 Scenario: How do you optimize vMotion performance?

✔ Answer:

 Use dedicated vMotion NICs, enable jumbo frames, and ensure sufficient bandwidth.'

'32 Scenario: A vSphere cluster is experiencing performance issues. What do you check?

✔ Answer:

 Monitor DRS settings, check host CPU/RAM, analyze storage latency, and review network bottlenecks.'

'33 Scenario: How do you upgrade VMware Tools on multiple VMs?

✔ Answer:

Use VMware Update Manager (VUM) for bulk upgrades.'

'34 Scenario: How do you automate VM provisioning?

✔ Answer:

 Use vSphere PowerCLI, Terraform, or vRealize Automation.'

'35 Scenario: How do you ensure vCenter database performance?

✔ Answer:

 Regularly clean logs, optimize SQL/PostgreSQL settings, and increase memory allocation.'

'36 Scenario: A vMotion migration fails. What do you check?

✔ Answer:

 Verify vMotion network, check host compatibility, and ensure DRS rules allow migration.'

'37 Scenario: How do you roll back a failed ESXi upgrade?

✔ Answer:

 Boot into the previous ESXi version using Shift + R during boot.'

'38 Scenario: A VM snapshot is taking too long to delete. What do you do?

✔ Answer:

 Consolidate snapshots manually and check storage performance.'

'39 Scenario: A VM needs to be cloned but with different settings. What’s the best approach?

✔ Answer:

 Use VM Customization Specifications during cloning.'

'40 Scenario: How do you monitor VMware performance?

✔ Answer:

 Use vRealize Operations Manager and ESXi Performance Charts.'
)

last_index=$(( ${#scenario_vmware[@]} - 1 ))


Total_questions="40"
echo " Total questions:$Total_questions"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_vmware[$i]}"
        echo " "
        echo " "
         echo " "
          echo " "
           echo " "
            echo " "
             echo " "
              echo " "
        read -p "Press Enter key to continue"
        clear
        echo " Total 40 questions"
done
clear
echo " End of questions. Thanks for participating"
    
	;;

  c)
      
VSPHERE_QUESTIONS=(
'What is a vSphere Cluster?|a) A collection of ESXi hosts that share resources|b) A group of virtual machines|c) A backup solution|d) A type of networking protocol|a'
'What is vSphere HA (High Availability)?|a) A backup system for virtual machines|b) A feature that restarts VMs on another host if the current host fails|c) A networking feature|d) A storage management system|b'
'What is vSphere vMotion used for?|a) Migrating running virtual machines between hosts without downtime|b) Backing up VMs|c) Creating new VMs automatically|d) Deleting unused VMs|a'
'Which protocol does vMotion use for migration?|a) FTP|b) HTTP|c) TCP/IP|d) UDP|c'
'Which feature balances the load on ESXi hosts by automatically moving VMs?|a) vMotion|b) Storage DRS|c) vSphere DRS (Distributed Resource Scheduler)|d) NSX|c'
'What is VMware vSAN?|a) A cloud service|b) A distributed storage solution for vSphere clusters|c) A network security tool|d) A VM backup tool|b'
'Which storage protocol is NOT supported by ESXi?|a) iSCSI|b) NFS|c) Fibre Channel|d) NTFS|d'
'What does VMFS stand for?|a) Virtual Machine File System|b) VMware Management Framework System|c) Virtual Machine Firmware Storage|d) Virtualized Memory File System|a'
'What is the maximum size of a VMFS-6 datastore?|a) 2 TB|b) 32 TB|c) 64 TB|d) 100 TB|c'
'Which VMware feature moves virtual machine storage without downtime?|a) vMotion|b) Storage vMotion|c) DRS|d) FT|b'
'What is a vSphere Standard Switch (vSS)?|a) A virtual switch used for networking within ESXi hosts|b) A physical network device|c) A firewall|d) A network monitoring tool|a'
'What is a vSphere Distributed Switch (vDS)?|a) A network switch that spans multiple ESXi hosts|b) A dedicated switch for virtual desktops|c) A physical network switch|d) A security feature|a'
'What is VMware NSX?|a) A network virtualization and security platform|b) A backup tool|c) A storage solution|d) A load balancer|a'
'Which protocol is used for VLAN tagging in vSphere?|a) TCP/IP|b) VLAN 802.1Q|c) SSL|d) SNMP|b'
'What is Network I/O Control (NIOC) used for?|a) Prioritizing network traffic in vSphere environments|b) Managing IP addresses|c) Creating virtual networks|d) Encrypting data packets|a'
'Which tool is used to manage VMware vSphere environments?|a) VMware Workstation|b) vCenter Server|c) Microsoft Hyper-V Manager|d) AWS Console|b'
'Which authentication method is commonly used in vSphere?|a) Local Authentication|b) Active Directory Integration|c) Single Sign-On (SSO)|d) All of the above|d'
'What is the purpose of VMware Fault Tolerance (FT)?|a) Creates a backup of VMs|b) Provides continuous availability by running a secondary VM|c) Encrypts virtual machine data|d) Improves networking speed|b'
'What is vSphere Update Manager (VUM) used for?|a) Updating VMware tools|b) Patching and upgrading ESXi hosts and VMs|c) Managing network security|d) Automating VM deployments|b'
'What is the main purpose of vSphere Role-Based Access Control (RBAC)?|a) Restricting access based on user roles|b) Encrypting virtual machines|c) Managing backup schedules|d) Speeding up vMotion|a'
'What happens if a host in a vSphere HA cluster fails?|a) All VMs are lost|b) VMs restart on another available host|c) The cluster shuts down|d) The host automatically repairs itself|b'
'What is required for VMware Fault Tolerance (FT) to work?|a) Shared storage and a secondary host|b) A physical backup server|c) A vMotion license|d) An external firewall|a'

'What is a slot size in vSphere HA?|a) The amount of CPU and memory reserved for failover capacity|b) The number of VMs per host|c) The total disk size per VM|d) The number of network ports per ESXi host|a'
'Which VMware feature ensures VM uptime during a host failure?|a) vSphere DRS|b) vSphere HA|c) Storage vMotion|d) vSphere Update Manager|b'
'What is Admission Control in vSphere HA?|a) A security feature to prevent unauthorized access|b) A mechanism to ensure enough resources are reserved for failover|c) A method to prevent overloading virtual networks|d) A backup configuration setting|b'
'What is VMware Data Protection (VDP) used for?|a) Encrypting data in vSphere|b) Backing up and restoring virtual machines|c) Creating snapshots for disaster recovery|d) Managing VM performance|b'
'What is a VM snapshot?|a) A full backup of a VM|b) A point-in-time copy of a VM’s disk and memory state|c) A clone of a VM|d) A migration process|b'
'What happens if too many snapshots are kept for a VM?|a) The VM runs faster|b) The VM storage usage increases and performance decreases|c) The VM network speed increases|d) Nothing, snapshots do not affect performance|b'
'Which VMware feature provides replication for disaster recovery?|a) vSphere Replication|b) vMotion|c) vSAN|d) DRS|a'
'What is VMware Site Recovery Manager (SRM)?|a) A tool for patching ESXi hosts|b) A disaster recovery automation tool|c) A feature for storage migration|d) A network monitoring solution|b'
'What is ESXTOP used for?|a) Managing vSphere licenses|b) Analyzing real-time performance metrics in ESXi|c) Configuring vSphere security|d) Setting up virtual networks|b'
'Which log file contains information about ESXi host issues?|a) /var/log/vmkernel.log|b) /var/log/httpd.log|c) /var/log/auth.log|d) /var/log/messages|a'
'What is the main cause of CPU Ready Time in vSphere?|a) High disk I/O|b) Network congestion|c) Too many vCPUs assigned to VMs|d) Insufficient RAM|c'
'What is the purpose of vSphere Performance Charts?|a) To monitor and analyze CPU, memory, and storage performance|b) To create backup schedules|c) To manage VM security settings|d) To generate network firewall rules|a'
'How can you reduce VM memory contention?|a) Increase the number of snapshots|b) Use memory ballooning and increase host RAM|c) Reduce the vCPU count|d) Disable vMotion|b'
'What is the difference between vSphere Standard and vSphere Enterprise Plus?|a) Enterprise Plus includes DRS, vSAN, and FT|b) Standard has more features|c) Enterprise Plus is free|d) There is no difference|a'
'What is VMware Tanzu used for?|a) Managing cloud storage|b) Running Kubernetes workloads on vSphere|c) Creating VM snapshots|d) Managing network security|b'
'What is VMware Cloud Foundation?|a) A software-defined data center (SDDC) platform|b) A backup tool for VMs|c) A network firewall|d) A monitoring system|a'
'How is vSphere licensed?|a) Per virtual machine|b) Per physical processor (CPU)|c) Per storage capacity|d) Per network port|b'
'What is VMware vSphere Auto Deploy used for?|a) Automatically installing and configuring ESXi hosts|b) Creating virtual networks|c) Encrypting VM disks|d) Managing Kubernetes clusters|a'

        )
SCORE=0
TOTAL_QUESTIONS=${#VSPHERE_QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Vmware Vsphere MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!VSPHERE_QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${VSPHERE_QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
         read -p "Press ENTER key to move to the next question"
        clear    
fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing Vmware Vsphere questions and answers! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;

esac
done

 ;;


 ii)
         while true; do
	 ## 
	  echo " You selected Microsoft Hyper-visor virtualization skill"
                                echo " "
                                echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"
                                echo " "
                                read -p "Select your way of study: " hyperv_way
                                case $hyperv_way in

 a)
         ## Place code here for

       clear
# Array of questions
hyperv_questions=(
'# Microsoft Hyper-V Interview Questions

1. What is Microsoft Hyper-V?

Answer:

        Microsoft Hyper-V is a virtualization platform that allows users to create and manage virtual machines on Windows systems.'
'2. What are the key features of Hyper-V?

Answer:

       Virtual machine isolation, live migration, dynamic memory, checkpointing, and nested virtualization.'
'3. How do you enable Hyper-V on Windows?

Answer:

      Open PowerShell as Administrator and run:
      Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All'
'4. What is a Hyper-V Virtual Switch?

Answer:

      A virtual switch in Hyper-V allows VMs to communicate with each other and external networks.'
'5. How do you create a virtual machine in Hyper-V?

Answer:

      Open Hyper-V Manager -> New -> Virtual Machine -> Follow the wizard.'
'6. What is Live Migration in Hyper-V?

Answer:

      Live Migration allows you to move a running virtual machine from one host to another with no downtime.'
'7. What are Hyper-V Checkpoints?

Answer:

      Checkpoints allow you to save the state of a VM and revert back if needed.'
'8. What is Dynamic Memory in Hyper-V?

Answer:

      Dynamic Memory allows Hyper-V to allocate memory dynamically based on VM demand.'
'9. How do you export and import a virtual machine in Hyper-V?

Answer:

      Use the Export and Import options in Hyper-V Manager.'
'10. How do you configure Hyper-V Replica?

Answer:

      Enable Hyper-V Replica on both hosts and configure replication settings.'
'11. What is Nested Virtualization?

Answer:

      Nested Virtualization allows you to run a VM inside another VM in Hyper-V.'
'12. How do you set up failover clustering in Hyper-V?

Answer:

      Use Windows Server Failover Clustering to enable high availability.'
'13. How do you allocate GPU resources to a VM?

Answer:

      Use RemoteFX or Discrete Device Assignment (DDA) for GPU sharing.'
'14. How do you enable enhanced session mode in Hyper-V?

Answer:

      Go to Hyper-V Settings -> Enhanced Session Mode Policy -> Enable.'
'15. What is Hyper-V Integration Services?

Answer:

      A set of services that improve communication between the host and VM.'
'16. How do you configure virtual network adapters in Hyper-V?

Answer:

      Use Hyper-V Manager -> VM Settings -> Add Hardware -> Network Adapter.'
'17. How do you monitor Hyper-V performance?

Answer:

      Use Performance Monitor, Resource Monitor, or Hyper-V Manager.'
'18. What is Shielded VM in Hyper-V?

Answer:

      Shielded VMs provide enhanced security using BitLocker encryption.'
'19. How do you automate Hyper-V management?

Answer:

      Use PowerShell commands like Get-VM, Start-VM, Stop-VM, etc.'
'20. How do you troubleshoot Hyper-V networking issues?

Answer:

      Use PowerShell, Event Viewer, and Hyper-V Manager logs to diagnose problems.'
'21. What is the difference between Type 1 and Type 2 Hypervisors?

Answer:

      Type 1 runs directly on hardware (bare-metal), while Type 2 runs on an OS.'
'22. How do you back up a Hyper-V virtual machine?

Answer:

      Use Windows Server Backup or a third-party backup solution.'
'23. What is Storage Live Migration?

Answer:

      Storage Live Migration moves a VMs storage without downtime.'
'24. How do you configure Hyper-V replication frequency?

Answer:

      Set replication intervals (30 sec, 5 min, 15 min) in Replica settings.'
'25. What is VMQ in Hyper-V?

Answer:

      Virtual Machine Queue (VMQ) improves network performance by offloading processing to NIC hardware.'
'26. How do you limit CPU usage in Hyper-V?

Answer:

      Use Hyper-V Manager -> VM Settings -> Processor -> Set resource control.'
'27. What are the different types of Hyper-V Virtual Switches?

Answer:

      External, Internal, and Private Virtual Switches.'
'28. How do you resize a virtual hard disk in Hyper-V?

Answer:

      Use Hyper-V Manager -> Edit Disk -> Expand or Shrink disk.'
'29. What is NUMA in Hyper-V?

Answer:

      Non-Uniform Memory Access (NUMA) optimizes memory access in multi-processor systems.'
'30. How do you enable SR-IOV in Hyper-V?

Answer:

      Use a compatible network adapter and enable SR-IOV in VM settings.'
)

last_index=$(( ${#hyperv_questions[@]} - 1 ))
Total_questions="${#hyperv_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${hyperv_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

        ;;

  b)
          ## place code here
	  clear
scenario_hyperv=(
'1 Scenario: A virtual machine (VM) is not starting in Hyper-V. How do you troubleshoot?

✔ Answer:

 Check if there are sufficient host resources (CPU,RAM,storage),verify if the VM is in a saved state, check the event logs,& ensure that the VMs VHDX file is not corrupt.'

'2 Scenario: You need to migrate a running VM to another Hyper-V host without downtime. What method do you use?

✔ Answer:

 Use Live Migration, which allows the transfer of VMs between Hyper-V hosts without downtime.'

'3 Scenario: A VM is running out of disk space. How do you increase its disk size?

✔ Answer:

 Shut down the VM, go to Hyper-V Manager, select the VM’s disk, and use the Edit Disk wizard to expand the VHDX. Then, extend the partition inside the guest OS.'

'4 Scenario: A VM is consuming too much CPU. How do you control it?

✔ Answer:

 Use CPU resource allocation settings to limit CPU usage, assign virtual NUMA nodes, or enable Dynamic Resource Allocation.'

'5 Scenario: How do you create a checkpoint (snapshot) of a VM?

✔ Answer:

 In Hyper-V Manager, right-click the VM and select Checkpoint. Alternatively, use Checkpoint-VM in PowerShell.'

'6 Scenario: A user accidentally deleted a VM. Can you restore it?

✔ Answer:

 If the VMs VHDX file still exists, create a new VM and attach the existing VHDX. If using Backup or Checkpoints, restore from a previous state.'

'7 Scenario: You need to automate VM creation in Hyper-V. What tools can you use?

✔ Answer:

 Use PowerShell (New-VM command) or System Center Virtual Machine Manager (SCVMM) for automation.'

'8 Scenario: You need to move a VM to another storage location. How do you do it?

✔ Answer:

 Use Storage Migration from Hyper-V Manager or PowerShell (Move-VMStorage).'

'9 Scenario: A VM loses network connectivity. What steps do you take?

✔ Answer:

 Verify if the virtual switch is configured correctly, check network adapter settings, and ensure the virtual NIC is connected.'

'10 Scenario: A host running Hyper-V crashes. What happens to its VMs?

✔ Answer:

 If Failover Clustering is configured, VMs automatically restart on another node. Otherwise, VMs remain offline until the host is restored.'

'11 Scenario: You need to isolate VM traffic on different VLANs. What feature do you use?

✔ Answer:

 Use Hyper-V Virtual Switch with VLAN tagging and assign VLAN IDs to VM network adapters.'

'12 Scenario: A VM needs direct access to a physical network adapter. How do you configure this?

✔ Answer:

 Use a Network Adapter in Bridged Mode or enable SR-IOV (Single Root I/O Virtualization).'

'13 Scenario: How do you enable DHCP services for VMs in Hyper-V?

✔ Answer:

 Use Windows Server DHCP Role, configure an Internal Virtual Switch, or use an external DHCP server.'

'14 Scenario: You need to provide network redundancy for a VM. What’s the best approach?

✔ Answer:

 Use NIC Teaming inside the VM or configure multiple virtual NICs connected to different virtual switches.'

'15 Scenario: A VM needs an isolated private network for testing. How do you achieve this?

✔ Answer:

 Create a Private Virtual Switch in Hyper-V, which allows communication between VMs but not with the host.'

'16 Scenario: How do you troubleshoot a VM that cannot communicate outside its network?

✔ Answer:

 Check Virtual Switch settings, verify IP/DNS configuration, check firewall rules, and test with tracert/ping.'

'17 Scenario: How do you configure Hyper-V to allow VM traffic to pass through a VPN?

✔ Answer:

 Use RRAS (Routing and Remote Access Service) on the host and configure NAT or enable VPN passthrough.'

'18 Scenario: A VM requires internet access but no direct access to the corporate network. How do you achieve this?

✔ Answer:

 Use NAT networking by setting up an Internal Virtual Switch and configuring Internet Connection Sharing (ICS) on the host.'

'19 Scenario: How do you configure a dedicated network adapter for Hyper-V replication?

✔ Answer:

 In Hyper-V Settings, configure Replication Network and bind it to a dedicated adapter.'

'20 Scenario: A VM is experiencing slow network performance. How do you troubleshoot?

✔ Answer:

 Check network adapter type (Legacy vs. Synthetic), enable VMQ (Virtual Machine Queue), and verify bandwidth settings.'

'21 Scenario: A VM’s VHDX file is growing rapidly. How do you manage it?

✔ Answer:

 Convert it to Fixed Size, enable Deduplication, or perform Compaction in Hyper-V Manager.'

'22 Scenario: How do you migrate a VM from a standalone Hyper-V host to a cluster?

✔ Answer:

 Use Shared Storage Migration or export/import the VM using PowerShell.'

'23 Scenario: You need to create a template for deploying multiple VMs. How do you do it?

✔ Answer:

 Use Sysprep on a base VM, convert it to a template, and deploy VMs using SCVMM or PowerShell.'

'24 Scenario: A Hyper-V host is running out of disk space. How do you resolve this?

✔ Answer:

 Compact dynamically expanding disks, delete unnecessary checkpoints, or migrate VMs to another storage location.'

'25 Scenario: A VM’s snapshot won’t delete. What do you do?

✔ Answer:

 Manually delete the AVHDX file, merge snapshots via PowerShell, or reboot the Hyper-V host.'

'26 Scenario: How do you ensure a VM is highly available?

✔ Answer:

 Configure Hyper-V Failover Clustering and store VM files on Cluster Shared Volumes (CSV).'

'27 Scenario: What happens if the Hyper-V host running a critical SQL VM crashes?

✔ Answer:

 If Failover Clustering is enabled, the VM restarts on another node. Otherwise, restore from backup.'

'28 Scenario: How do you set up offsite disaster recovery for Hyper-V?

✔ Answer:

 Use Hyper-V Replica to replicate VMs to a remote site.'

'29 Scenario: A VM backup has failed. How do you troubleshoot?

✔ Answer:

 Check if Volume Shadow Copy Service (VSS) is enabled, ensure backup integration services are running, and verify available storage.'

'30 Scenario: You need to restore a deleted VM. What options do you have?

✔ Answer:

 Restore from backup, use Previous Versions, or recreate the VM and attach the existing VHDX.'

'31 Scenario: How do you monitor Hyper-V performance?

✔ Answer:

 Use Performance Monitor, Resource Metering, and SCVMM Reports.'

'32 Scenario: A VM needs more RAM but without rebooting. What feature do you use?

✔ Answer:

 Enable Dynamic Memory allocation.'

'33 Scenario: How do you protect Hyper-V against ransomware?

✔ Answer:

 Use Shielded VMs, BitLocker, and regular backups.'

'34 Scenario: How do you test a Hyper-V HA failover scenario?

✔ Answer:

 Manually shut down a Hyper-V node and observe if VMs restart on another node.'

'35 Scenario: A VM takes too long to boot. What do you check?

✔ Answer:

 Analyze boot logs, check disk IOPS, and optimize startup applications.'
)
last_index=$(( ${#scenario_hyperv[@]} - 1 ))
Total_questions="35"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_hyperv[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo "  "
        echo ""
        read -p "Press Enter key to continue..."
        clear
        echo 'Total 35 questions'
done
clear
echo " End of questions. Thanks for participating"

        ;;

  c)

clear
QUESTIONS=(

'What is Microsoft Hyper-V?|a) A type-2 hypervisor|b) A virtualization platform for Windows|c) A Linux-based container manager|d) A cloud storage service|b'
'Which Windows editions support Hyper-V?|a) Windows 10/11 Home|b) Windows 10/11 Pro & Enterprise, Windows Server|c) Windows 7 Ultimate|d) macOS|b'
'What is the primary function of Hyper-V?|a) Running Android applications|b) Virtualizing operating systems|c) Managing databases|d) Automating scripts|b'
'What is the Hyper-V hypervisor type?|a) Type-1 (bare-metal)|b) Type-2 (hosted)|c) Cloud-based|d) Hybrid|a'
'Which command enables Hyper-V on Windows?|a) Enable-WindowsFeature -Name Hyper-V|b) Install-Hyper-V|c) start-hyperv|d) enable-vmware|a'
'What is the default virtual disk format in Hyper-V?|a) .vhd / .vhdx|b) .vmdk|c) .iso|d) .qcow2|a'
'What is the difference between .vhd and .vhdx?|a) .vhd supports larger disk sizes|b) .vhdx supports larger disk sizes and resilience to corruption|c) Both are identical|d) .vhdx is used for Linux VMs only|b'
'What is the maximum disk size supported by .vhdx?|a) 2 TB|b) 32 TB|c) 64 TB|d) 16 TB|c'
'What type of virtual disks does Hyper-V support?|a) Fixed, Dynamic, and Differencing|b) Persistent and Non-Persistent|c) Raw and Encrypted|d) SSD and HDD|a'
'What is a differencing disk?|a) A disk that stores only changes from the parent disk|b) A backup copy of a virtual disk|c) A read-only disk|d) A disk that automatically resizes|a'
'What are the types of Hyper-V virtual switches?|a) Public, Private, and Hybrid|b) Internal, External, and Private|c) NAT, Routed, and Bridged|d) Static, Dynamic, and VLAN|b'
'What does an external virtual switch do?|a) Connects VMs only to each other|b) Connects VMs to the host and external network|c) Blocks all network traffic|d) Allows only outbound connections|b'
'What does a private virtual switch do?|a) Connects VMs to external networks|b) Blocks all network traffic|c) Allows communication only between VMs on the host|d) Bridges the VM network to the internet|c'
'What is a VLAN in Hyper-V?|a) A backup system for VMs|b) A virtual network for isolating traffic|c) A storage system|d) A physical NIC driver|b'
'How do you configure a Hyper-V virtual switch?|a) Through PowerShell|b) Through Hyper-V Manager|c) Using Virtual Switch Manager|d) All of the above|d'
'What is Hyper-V Live Migration?|a) Moving VMs between hosts without downtime|b) Copying a VM’s data to a backup server|c) Running VMs on the cloud|d) Restoring a VM from a snapshot|a'
'What is Hyper-V Replica?|a) A VM backup tool|b) A disaster recovery feature for VM replication|c) A feature for scaling VMs|d) A snapshot tool|b'
'What is Hyper-V Dynamic Memory?|a) A feature that automatically adjusts VM memory usage|b) A disk caching feature|c) A method for increasing VM storage|d) A security feature|a'
'What does Hyper-V Shielded VM provide?|a) Encryption and security for VMs|b) Better performance|c) Larger disk sizes|d) Automated backups|a'
'What is Hyper-V Nested Virtualization?|a) Running a VM inside another VM|b) Running VMs on cloud infrastructure|c) Enabling GPU acceleration for VMs|d) Running Linux VMs|a'
'Which tool manages Hyper-V on Windows Server?'
'a) Hyper-V Manager|b) vSphere|c) Oracle VM Manager|d) Docker|a'
'How can you enable Hyper-V on Windows 10?'
'a) Control Panel → Programs & Features → Turn Windows features on/off|b) Registry Editor|c) Task Manager|d) BIOS settings|a'
'What is the default checkpoint type in Hyper-V?'
'a) Standard Checkpoint|b) Production Checkpoint|c) Linked Clone|d) Snapshot Checkpoint|b'
'What does Hyper-V Enhanced Session Mode allow?'
'a) Clipboard sharing, audio, and USB redirection|b) Faster boot times|c) VM replication|d) Disk encryption|a'
'What is the Hyper-V role in Windows Server?'
'a) A software development kit|b) A Windows feature for creating and managing virtual machines|c) A web hosting service|d) A firewall feature|b'
'What is Hyper-V Storage Migration?'
'a) Moving virtual machines to the cloud|b) Moving a virtual disk to another storage location while the VM is running|c) Migrating Hyper-V settings to a new host|d) Backing up virtual disks|b'
'Which feature reduces storage space by eliminating duplicate data in Hyper-V?'
'a) Storage Spaces|b) Deduplication|c) Dynamic Memory|d) Disk Mirroring|b'
'What is the maximum number of vCPUs a VM can have in Hyper-V?'
'a) 32|b) 64|c) 240|d) 512|c'
'What type of storage does Hyper-V support for virtual machines?'
'a) Local storage|b) Network-attached storage (NAS)|c) Storage area network (SAN)|d) All of the above|d'
'What does Hyper-V Resource Metering do?'
'a) Tracks VM resource usage (CPU, memory, network, disk)|b) Allocates network bandwidth|c) Monitors CPU temperatures|d) Manages software licensing|a'
'What is NIC Teaming in Hyper-V?'
'a) Combining multiple network interfaces for redundancy and performance|b) Creating virtual networks|c) Isolating VM traffic|d) Assigning a static IP address|a'
'What is the benefit of SR-IOV (Single Root I/O Virtualization) in Hyper-V?'
'a) Increases disk performance|b) Reduces network latency by bypassing the host OS|c) Enables GPU acceleration|d) Provides built-in firewall protection|b'
'What is Hyper-V Failover Clustering?'
'a) A method to migrate storage|b) A feature for high availability by moving VMs to another host if a failure occurs|c) A way to increase CPU performance|d) A backup feature|b'
'What is Network Virtualization in Hyper-V?'
'a) A method to encrypt virtual machine networks|b) A feature that isolates VM traffic from physical networks|c) A way to back up VMs over the network|d) A network adapter for physical machines|b'
'What is the purpose of Quality of Service (QoS) in Hyper-V?'
'a) Limiting network bandwidth for VMs|b) Increasing disk performance|c) Monitoring power consumption|d) Encrypting virtual networks|a'
'Which feature allows you to restore a VM to a previous state?'
'a) Checkpoints|b) Storage Migration|c) Live Migration|d) Virtual Switch|a'
'Which Windows feature is commonly used for backing up Hyper-V VMs?'
'a) Windows Server Backup|b) Notepad|c) Hyper-V Manager|d) DHCP Server|a'
'How does Hyper-V Replica work?'
'a) It creates a copy of a VM on a remote server for disaster recovery|b) It performs live migration|c) It encrypts VM files|d) It clones a VM instantly|a'
'Which tool is used to automate Hyper-V backups?'
'a) PowerShell|b) VMware Workstation|c) Hyper-V Dynamic Memory|d) vSphere Client|a'
'What is the recommended method for securing Hyper-V backups?'
'a) Storing backups on the same VM|b) Keeping multiple copies in different locations|c) Using a single backup file|d) Only using cloud storage|b'
'What is Azure Site Recovery (ASR)?'
'a) A cloud-based disaster recovery solution for Hyper-V|b) A database backup service|c) A file-sharing system|d) A virtualization tool|a'
'What is a Hybrid Cloud in the context of Hyper-V?'
'a) Running VMs only on-premises|b) Using both on-premises and cloud-based Hyper-V workloads|c) Running only Linux VMs|d) Using Hyper-V on mobile devices|b'
'How can Hyper-V VMs be managed remotely?'
'a) Using Hyper-V Manager|b) PowerShell Remoting|c) System Center Virtual Machine Manager (SCVMM)|d) All of the above|d'
'What is Windows Admin Center?'
'a) A web-based tool for managing Hyper-V and other Windows Server features|b) A disk cleanup utility|c) A programming interface|d) A Linux-only virtualization tool|a'
'Which Hyper-V feature allows running Linux virtual machines efficiently?'
'a) Shielded VM|b) Linux Integration Services (LIS)|c) Storage Spaces|d) Failover Clustering|b'
'What is the minimum RAM required to run Hyper-V on Windows 10/11?'
'a) 2 GB|b) 4 GB|c) 8 GB|d) 16 GB|b'
'How can you check if a system supports Hyper-V?'
'a) Running systeminfo in Command Prompt|b) Checking Task Manager|c) Using Device Manager|d) Installing VMware|a'
'What happens when you delete a VM from Hyper-V Manager?'
'a) The VM is permanently deleted along with its virtual disk|b) The VM is stopped but its files remain|c) The VM is moved to the recycle bin|d) The VM is archived|b'
'How can you increase a VM’s CPU allocation in Hyper-V?'
'a) By modifying the VM settings and increasing vCPU count|b) By reinstalling the VM|c) By installing additional network adapters|d) By enabling the "Performance Mode" option|a'
'What command lists all running VMs in Hyper-V using PowerShell?'
'a) Get-VM|b) List-VMs|c) Show-VMs|d) Check-VM|a'
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Microsoft Hyper-visor MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
         read -p "Press ENTER key to move to the next question"
         clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Microsoft Hyper-visor! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;

esac
done
    ;;

 iii)
         while true; do
	 echo " You selected Oracle virtaul machine manager skill"
                                echo " "
                                echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"
                                echo " "
                                read -p "Select your way of study: " oraclevm_way
                                case $oraclevm_way in

 a)
         ## Place code here for
         clear

oraclevm_questions=(
"1. What is Oracle VM Manager?

Answer:

       Oracle VM Manager is a web-based management interface that allows users to create, configure, and manage Oracle VM Server environments."

"2. What is the difference between Oracle VM Manager and Oracle VM Server?

Answer:

       Oracle VM Manager provides a centralized management interface, while Oracle VM Server is the hypervisor that runs virtual machines."

"3. What are the key components of Oracle VM?

Answer:

       The key components include:
       - Oracle VM Manager
       - Oracle VM Server
       - Oracle VM Agent
       - Oracle VM Storage Repository"

"4. How does Oracle VM Manager communicate with Oracle VM Server?

Answer:

       Oracle VM Manager communicates with Oracle VM Server using Oracle VM Agent over a secure network connection."

"5. What is an Oracle VM Repository?

Answer:

       An Oracle VM Repository is a shared storage location that stores virtual machine resources such as images, templates, and ISO files."

"6. What storage types does Oracle VM Manager support?

Answer:

       Oracle VM supports:
       - NFS (Network File System)
       - iSCSI (Internet Small Computer System Interface)
       - Fibre Channel"

"7. What are Oracle VM templates?

Answer:

       Oracle VM templates are pre-configured virtual machine images that help in rapid deployment of Oracle applications."

"8. What is a VM pool in Oracle VM?

Answer:

       A VM pool is a collection of Oracle VM Servers that share resources for high availability and workload balancing."

"9. What is the difference between Live Migration and Cold Migration in Oracle VM?

Answer:

       - Live Migration moves a running VM from one host to another without downtime.
       - Cold Migration requires the VM to be shut down before being moved."

"10. What is the purpose of Oracle VM Agent?

Answer:

       Oracle VM Agent runs on Oracle VM Server and enables communication between Oracle VM Manager and Oracle VM Server."

"11. How do you create a new VM in Oracle VM Manager?

Answer:

       A new VM can be created by:
       - Using VM templates
       - Importing an existing virtual machine image
       - Installing from an ISO file"

"12. What is High Availability (HA) in Oracle VM?

Answer:

       HA ensures that VMs automatically restart on another available host if the current host fails."

"13. What is the function of the Oracle VM CLI (Command Line Interface)?

Answer:

       The Oracle VM CLI allows users to manage Oracle VM environments through command-line commands instead of the web-based interface."

"14. What are the steps to migrate a virtual machine in Oracle VM?

Answer:

       - Ensure the VM is not pinned to a specific host.
       - Use Live Migration for running VMs or Cold Migration for powered-off VMs.
       - Verify shared storage is accessible from both hosts."

"15. How does Oracle VM handle virtual networking?

Answer:

       Oracle VM provides network isolation, VLAN support, and multiple network types such as:
       - Server Management Network
       - Storage Network
       - Virtual Machine Network"

"16. What is the function of an Oracle VM server pool?

Answer:

       A server pool groups Oracle VM Servers together for resource sharing, load balancing, and high availability."

"17. What hypervisor technology does Oracle VM use?

Answer:

       Oracle VM is based on the open-source Xen hypervisor, optimized for Oracle workloads."

"18. What is the purpose of the Oracle VM Manager database?

Answer:

       The Oracle VM Manager database stores configuration data, VM details, and system logs."

"19. What is the difference between Oracle VM and VMware?

Answer:

       - Oracle VM is optimized for Oracle workloads and uses Xen, while VMware uses its own ESXi hypervisor.
       - Oracle VM is free, while VMware requires licensing for enterprise features."

"20. How can you back up Oracle VM Manager?

Answer:

       - Back up the Oracle VM Manager database.
       - Export VM templates and configurations.
       - Use Oracle VM backup utilities."

"21. How do you monitor Oracle VM performance?

Answer:

       - Use Oracle VM Manager's built-in monitoring tools.
       - Integrate with Oracle Enterprise Manager for advanced monitoring."

"22. What is the importance of the Oracle VM utility repository?

Answer:

       It stores utility resources such as scripts, drivers, and software updates."

"23. How do you update Oracle VM Server software?

Answer:

       - Download patches from Oracle Support.
       - Apply updates using Oracle VM Manager or YUM package management."

"24. What happens if Oracle VM Manager fails?

Answer:

       - Running VMs continue to operate, but new configurations cannot be made.
       - A backup Oracle VM Manager instance can be restored to resume management."

"25. Can Oracle VM run non-Oracle workloads?

Answer:

       Yes, Oracle VM supports various guest operating systems, including Linux and Windows."

"26. What are the security features of Oracle VM?

Answer:

       - Role-based access control (RBAC)
       - Encrypted network traffic
       - Secure VM isolation"

"27. What is the role of the Oracle VM Storage Connect framework?

Answer:

       It provides integration with third-party storage providers for improved storage management."

"28. How do you clone a VM in Oracle VM Manager?

Answer:

       - Select the VM from Oracle VM Manager.
       - Use the Clone option to create an identical copy."

"29. What are Oracle VM Virtual Disks?

Answer:

       Virtual disks are logical storage devices used by VMs instead of physical disks."

"30. How do you shut down an Oracle VM Server?

Answer:

       - Use Oracle VM Manager to gracefully shut down.
       - Use the CLI command: `shutdown -h now` on the server."


)

last_index=$(( ${#oraclevm_questions[@]} - 1 ))
Total_questions="30"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${oraclevm_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo ' Total 30 questions'
done
clear
echo "End of questions. Thanks for participating"

        ;;

  b)
          ## place code here
	  clear
v="$session"
scenario_sql=(
"Basic SQL Scenarios (1-10)
1 Scenario: How do you retrieve all records from a table named 'employees'?

✔ Answer: Use the query:

SELECT * FROM employees;"
"2 Scenario: How do you find employees with a salary greater than 50,000

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary > 50000;"
"3 Scenario: How do you get the total number of employees in a department

✔ Answer: Use the query:

SELECT department_id, COUNT(*) FROM employees GROUP BY department_id;"
"4 Scenario: How do you retrieve the highest salary in the company

✔ Answer: Use the query:

SELECT MAX(salary) FROM employees;"
"5 Scenario: How do you fetch employees whose names start with 'A'

✔ Answer: Use the query:

SELECT * FROM employees WHERE name LIKE 'A%';"
"6 Scenario: How do you find duplicate records in a table

✔ Answer: Use the query:

SELECT column_name, COUNT(*)
FROM table_name
GROUP BY column_name
HAVING COUNT(*) > 1;"
"7 Scenario: How do you delete duplicate rows from a table while keeping one copy

✔ Answer: Use the query:

DELETE FROM employees
WHERE rowid NOT IN (SELECT MIN(rowid) FROM employees GROUP BY name, salary);"
"8 Scenario: How do you update salaries by 10% for all employees

✔ Answer: Use the query:

UPDATE employees SET salary = salary * 1.10;"
"9 Scenario: How do you get the first three highest salaries

✔ Answer: Use the query:

SELECT DISTINCT salary
FROM employees
ORDER BY salary DESC
FETCH FIRST 3 ROWS ONLY;"
"10 Scenario: How do you retrieve employees who joined in the last 30 days

✔ Answer: Use the query:

SELECT * FROM employees WHERE hire_date >= SYSDATE - 30;
Intermediate SQL Scenarios (11-20)"
"11 Scenario: How do you check if a table exists in Oracle SQL

✔ Answer: Use the query:

SELECT table_name FROM user_tables WHERE table_name = 'EMPLOYEES';"
"12 Scenario: How do you rename a column in an existing table

✔ Answer: Use the query:

ALTER TABLE employees RENAME COLUMN old_name TO new_name;"
"13 Scenario: How do you find employees with NULL values in their email column

✔ Answer: Use the query:

SELECT * FROM employees WHERE email IS NULL;"
"14 Scenario: How do you add a new column 'bonus' to the employees table

✔ Answer: Use the query:

ALTER TABLE employees ADD bonus NUMBER(10,2);"
"15 Scenario: How do you get the current date and time in Oracle SQL

✔ Answer: Use the query:

SELECT SYSDATE FROM dual;"
"16 Scenario: How do you concatenate first and last names in the employees table

✔ Answer: Use the query:

SELECT first_name || ' ' || last_name AS full_name FROM employees;"
"17 Scenario: How do you create an index on the 'email' column of the employees table

✔ Answer: Use the query:

CREATE INDEX email_idx ON employees(email);"
"18 Scenario: How do you check the structure of a table

✔ Answer: Use the query:

DESC employees;"
"19 Scenario: How do you fetch employees who joined between two dates

✔ Answer: Use the query:

SELECT * FROM employees WHERE hire_date BETWEEN '01-JAN-2023' AND '31-DEC-2023';"
"20 Scenario: How do you list all constraints on a table

✔ Answer: Use the query:

SELECT constraint_name, constraint_type
FROM user_constraints
WHERE table_name = 'EMPLOYEES';
Advanced SQL Scenarios (21-30)"
"21 Scenario: How do you fetch the second highest salary in the employees table

✔ Answer: Use the query:

SELECT DISTINCT salary FROM employees ORDER BY salary DESC OFFSET 1 ROW FETCH NEXT 1 ROW ONLY;"
"22 Scenario: How do you count the number of rows in a table

✔ Answer: Use the query:

SELECT COUNT(*) FROM employees;"
"23 Scenario: How do you drop a table permanently

✔ Answer: Use the query:

DROP TABLE employees;"
"24 Scenario: How do you create a view to display employees earning above 60,000

✔ Answer: Use the query:

CREATE VIEW high_salary_employees AS
SELECT * FROM employees WHERE salary > 60000;"
"25 Scenario: How do you check all indexes on a table

✔ Answer: Use the query:

SELECT index_name FROM user_indexes WHERE table_name = 'EMPLOYEES';"
"26 Scenario: How do you list all stored procedures in a database

✔ Answer: Use the query:

SELECT object_name FROM user_procedures;"
"27 Scenario: How do you find the length of a string in SQL

✔ Answer: Use the query:

SELECT LENGTH('Oracle SQL') FROM dual;"
"28 Scenario: How do you round a decimal value to 2 places

✔ Answer: Use the query:

SELECT ROUND(123.4567, 2) FROM dual;"
"29 Scenario: How do you fetch employees with salaries between 40,000 and 70,000

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary BETWEEN 40000 AND 70000;"
"30 Scenario: How do you change the datatype of a column

✔ Answer: Use the query:

ALTER TABLE employees MODIFY salary NUMBER(12,2);
Expert-Level SQL Scenarios (31-50)"
"31 Scenario: How do you find employees whose salary is the same as another employee

✔ Answer: Use the query:

SELECT e1.* FROM employees e1 JOIN employees e2 ON e1.salary = e2.salary AND e1.employee_id <> e2.employee_id;"
"32 Scenario: How do you create a foreign key in Oracle SQL

✔ Answer: Use the query:

ALTER TABLE orders ADD CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id);"
"33 Scenario: How do you get the first 5 records of a table

✔ Answer: Use the query:

SELECT * FROM employees FETCH FIRST 5 ROWS ONLY;


Expert-Level SQL Scenarios (34-50)"
"34 Scenario: How do you create a stored procedure to increase employee salaries by 10%

✔ Answer: Use the query:

CREATE PROCEDURE increase_salary AS
BEGIN
    UPDATE employees SET salary = salary * 1.10;
    COMMIT;
END;"
"35 Scenario: How do you fetch the nth highest salary from a table

✔ Answer: Use the query:

SELECT DISTINCT salary FROM employees ORDER BY salary DESC OFFSET (n-1) ROWS FETCH NEXT 1 ROW ONLY;"
"36 Scenario: How do you list all columns of a table

✔ Answer: Use the query:

SELECT column_name FROM user_tab_columns WHERE table_name = 'EMPLOYEES';"
"37 Scenario: How do you remove a column from a table

✔ Answer: Use the query:

ALTER TABLE employees DROP COLUMN bonus;"
"38 Scenario: How do you check if a value exists in a table

✔ Answer: Use the query:

SELECT 1 FROM employees WHERE employee_id = 100;"
"39 Scenario: How do you find the employees with the lowest salary

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary = (SELECT MIN(salary) FROM employees);"
"40 Scenario: How do you update multiple rows with different values

✔ Answer: Use the query:

UPDATE employees SET salary =
  CASE WHEN department_id = 10 THEN salary * 1.10
       WHEN department_id = 20 THEN salary * 1.05
       ELSE salary
  END;"
"41 Scenario: How do you fetch employees whose hire date is in February

✔ Answer: Use the query:

SELECT * FROM employees WHERE TO_CHAR(hire_date, 'MM') = '02';"
"42 Scenario: How do you delete all records from a table without deleting the structure

✔ Answer: Use the query:

TRUNCATE TABLE employees;"
"43 Scenario: How do you find all tables in the database owned by the current user

✔ Answer: Use the query:

SELECT table_name FROM user_tables;"
"44 Scenario: How do you list all sequences in the database

✔ Answer: Use the query:

SELECT sequence_name FROM user_sequences;"
"45 Scenario: How do you create a sequence to generate unique employee IDs

✔ Answer: Use the query:

CREATE SEQUENCE emp_id_seq START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;"
"46 Scenario: How do you use a sequence in an INSERT statement

✔ Answer: Use the query:

INSERT INTO employees (employee_id, name, salary)
VALUES (emp_id_seq.NEXTVAL, 'John Doe', 60000);"
"47 Scenario: How do you remove all employees who have been terminated

✔ Answer: Use the query:

DELETE FROM employees WHERE status = 'Terminated';"
"48 Scenario: How do you check database session information

✔ Answer: Use the query:

SELECT * FROM echo v$ session;"
"49 Scenario: How do you join two tables to fetch employee names and department names

✔ Answer: Use the query:

SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department_id = d.department_id;"
"50 Scenario: How do you fetch the last inserted record in a table

✔ Answer: Use the query:

SELECT * FROM employees WHERE rowid = (SELECT MAX(rowid) FROM employees);"

)

last_index=$(( ${#scenario_sql[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_sql[$i]}"
        echo " "
         echo " "
          echo " "
           echo " "
            echo " "
             echo " "
              echo " "
               echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 50 questions'
done
clear
echo " End of questions. Thanks for participating"

        ;;

  c)

QUESTIONS=(
    "What is SQL?|a) A programming language|b) A query language|c) A markup language|d) A scripting language|b"
    "Which SQL command is used to retrieve data from a database?|a) GET|b) SELECT|c) FETCH|d) RETRIEVE|b"
    "What does the acronym DDL stand for?|a) Data Definition Language|b) Data Deployment Language|c) Dynamic Data Language|d) Data Derivation Language|a"
    "Which of the following is a DML command?|a) CREATE|b) ALTER|c) INSERT|d) DROP|c"
    "Which SQL clause is used to filter results?|a) WHERE|b) ORDER BY|c) GROUP BY|d) FILTER|a"
    "What does the JOIN clause do in SQL?|a) Merges two databases|b) Combines rows from two or more tables|c) Sorts query results|d) Removes duplicate records|b"
    "Which SQL statement is used to remove all records from a table without deleting the table itself?|a) DELETE|b) DROP|c) TRUNCATE|d) REMOVE|c"
    "What is the purpose of the GROUP BY clause?|a) Sorts query results|b) Aggregates data by column values|c) Filters data|d) Removes duplicate records|b"
    "Which SQL function is used to count the number of rows?|a) SUM()|b) COUNT()|c) AVG()|d) MAX()|b"
    "Which constraint is used to ensure all values in a column are unique?|a) NOT NULL|b) UNIQUE|c) CHECK|d) PRIMARY KEY|b"
    "What is a primary key?|a) A unique identifier for each row in a table|b) A foreign key reference|c) A column that stores indexes|d) A table constraint|a"
    "Which SQL command is used to modify existing records in a table?|a) CHANGE|b) UPDATE|c) MODIFY|d) ALTER|b"
    "What does the HAVING clause do?|a) Filters aggregate results|b) Orders query results|c) Joins tables|d) Groups query results|a"
    "Which SQL keyword is used to retrieve unique values?|a) DISTINCT|b) UNIQUE|c) DIFFERENT|d) SEPARATE|a"
    "Which of the following is a valid SQL data type?|a) INT|b) DECIMAL|c) VARCHAR|d) All of the above|d"
    "What is the default sorting order of ORDER BY?|a) ASC|b) DESC|c) RANDOM|d) NONE|a"
    "Which statement is used to create a new table in SQL?|a) MAKE TABLE|b) NEW TABLE|c) CREATE TABLE|d) ADD TABLE|c"
    "Which SQL keyword is used to delete a table permanently?|a) REMOVE|b) DELETE|c) DROP|d) ERASE|c"
    "What is a foreign key?|a) A key from another table linking relationships|b) A unique column identifier|c) A primary key|d) A stored procedure|a"
    "Which operator is used for pattern matching in SQL?|a) LIKE|b) MATCH|c) SEARCH|d) FIND|a"
    "Which function returns the current date in SQL?|a) GETDATE()|b) CURDATE()|c) NOW()|d) All of the above|d"
    "What is an index in SQL?|a) A lookup table to speed up queries|b) A method to insert records|c) A table constraint|d) A stored procedure|a"
    "Which SQL clause is used to rename a column?|a) CHANGE|b) MODIFY|c) AS|d) ALTER COLUMN|c"
    "What is normalization in SQL?|a) Reducing data redundancy|b) Increasing data redundancy|c) Deleting data|d) Backing up data|a"
    "Which SQL function calculates the average value of a column?|a) SUM()|b) AVG()|c) COUNT()|d) MIN()|b"
    "What is a stored procedure?|a) A predefined SQL script|b) A temporary table|c) A function that updates records|d) A backup process|a"
    "Which SQL command is used to create an index?|a) MAKE INDEX|b) NEW INDEX|c) CREATE INDEX|d) ADD INDEX|c"
    "What is a view in SQL?|a) A virtual table|b) A stored procedure|c) A database function|d) A constraint|a"
    "Which SQL clause is used to check for a null value?|a) = NULL|b) IS NULL|c) CHECK NULL|d) FIND NULL|b"
    "Which command is used to roll back a transaction?|a) ROLLBACK|b) UNDO|c) CANCEL|d) REVERSE|a"
    "Which SQL statement is used to add new columns to a table?|a) MODIFY TABLE|b) ADD COLUMN|c) ALTER TABLE|d) CHANGE TABLE|c"
    "Which SQL function finds the highest value in a column?|a) MIN()|b) AVG()|c) MAX()|d) COUNT()|c"
    "What is a composite key?|a) A key composed of multiple columns|b) A primary key|c) A foreign key|d) A unique constraint|a"
    "Which SQL statement removes duplicate rows?|a) DELETE DISTINCT|b) UNIQUE|c) DISTINCT|d) FILTER|c"
    "What does the UNION operator do?|a) Combines results from multiple SELECT statements|b) Joins two tables|c) Merges data types|d) Deletes duplicates|a"
    "What is the difference between UNION and UNION ALL?|a) UNION removes duplicates, UNION ALL does not|b) UNION ALL removes duplicates, UNION does not|c) UNION is faster|d) There is no difference|a"
    "Which SQL clause is used to check a condition in a query?|a) IF|b) CASE|c) CHECK|d) VERIFY|b"
    "Which SQL function finds the lowest value in a column?|a) MIN()|b) AVG()|c) MAX()|d) COUNT()|a"
    "Which keyword is used to remove an existing view?|a) DELETE VIEW|b) DROP VIEW|c) REMOVE VIEW|d) ERASE VIEW|b"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Oracle SQL MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Oracle SQL! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;

 esac
 done
    ;;

 iv)
         while true; do
	 echo " You selected Redhat virtaul machine manager skill"
                                echo " "
                                echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"
                                echo " "
                                read -p "Select your way of study: " rhelvm_way
                                case $rhelvm_way in



 a)
         ## Place code here for rhelvm_question
        clear
# Array of questions
rhvm_questions=(
'# RHVM Interview Questions

1. What is RHVM?

Answer:

        RHVM (Red Hat Virtualization Manager) is a management tool used to manage and deploy virtual machines in a Red Hat Virtualization (RHV) environment.'
'2. What are the key components of RHVM?

Answer:

       RHV Manager, Hypervisor (RHV-H), Storage, and Networking.'
'3. How do you install RHVM?

Answer:

      Install the RHV-M package on a dedicated management server and configure it using the engine-setup command.'
'4. How do you access the RHVM web interface?

Answer:

      Open a browser and navigate to https://<RHVM-IP>:443/ovirt-engine.'
'5. What is a Data Center in RHVM?

Answer:

      A logical container that includes clusters, storage, and network configurations.'
'6. How do you create a virtual machine in RHVM?

Answer:

      RHVM Console -> Compute -> Virtual Machines -> New VM.'
'7. What is a Storage Domain in RHVM?

Answer:

      A logical storage unit that contains VM disks, ISO images, and snapshots.'
'8. How do you add a new host to RHVM?

Answer:

      RHVM Console -> Compute -> Hosts -> Add -> Enter Host details and approve.'
'9. What types of storage domains are supported in RHVM?

Answer:

      NFS, iSCSI, GlusterFS, and Fibre Channel.'
'10. How do you migrate a VM between hosts in RHVM?

Answer:

      RHVM Console -> Compute -> Virtual Machines -> Select VM -> Migrate.'
'11. What is a Cluster in RHVM?

Answer:

      A group of hosts with shared storage and networking settings.'
'12. How do you enable High Availability for a VM?

Answer:

      Edit VM settings and enable HA under "High Availability" options.'
'13. What is Live Storage Migration in RHVM?

Answer:

      Moving a VM’s disk between storage domains without downtime.'
'14. How do you check the RHVM logs?

Answer:

      Check logs in /var/log/ovirt-engine/.'
'15. What is a Template in RHVM?

Answer:

      A pre-configured VM image used to create multiple identical VMs.'
'16. How do you create a VM snapshot in RHVM?

Answer:

      RHVM Console -> Compute -> Virtual Machines -> Select VM -> Create Snapshot.'
'17. What is the purpose of the oVirt Engine service?

Answer:

      It is the central management service responsible for handling VM, storage, and network operations.'
'18. How do you restart the RHVM engine service?

Answer:

      systemctl restart ovirt-engine.'
'19. How do you monitor RHVM performance?

Answer:

      Use the built-in dashboard and logs or integrate with Grafana and Prometheus.'
'20. What is Hosted Engine in RHVM?

Answer:

      A self-hosted RHV Manager running as a VM on the RHV cluster itself.'
'21. How do you upgrade RHVM?

Answer:

      Update RHV packages using yum/dnf and run engine-setup.'
'22. What is the difference between RHVM and OpenStack?

Answer:

      RHVM is focused on virtual machine management, while OpenStack provides a broader cloud computing framework.'
'23. How do you assign CPU and memory resources to a VM?

Answer:

      RHVM Console -> Compute -> Virtual Machines -> Edit VM -> Adjust CPU and memory settings.'
'24. What is Affinity Group in RHVM?

Answer:

      A policy that ensures VMs run together (positive affinity) or separately (negative affinity).'
'25. How do you import an external VM into RHVM?

Answer:

      Use the “Import VM” feature in RHVM or convert using virt-v2v.'
'26. What is the purpose of the VDSM service in RHVM?

Answer:

      VDSM (Virtual Desktop and Server Manager) manages hypervisors and communicates with the RHVM engine.'
'27. How do you enable fencing in RHVM?

Answer:

      Configure fencing agents in RHVM settings for cluster hosts.'
'28. How do you create a custom role in RHVM?

Answer:

      RHVM Console -> Administration -> Roles -> Create New Role and define permissions.'
'29. What is the role of Ansible in RHVM?

Answer:

      Ansible automates RHVM operations such as VM provisioning and configuration management.'
'30. How do you configure RHVM backup?

Answer:

      Use engine-backup command to take a backup of the RHVM database and settings.'
)

last_index=$(( ${#rhvm_questions[@]} - 1 ))
Total_questions="${#rhvm_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${rhvm_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"


        ;;

  b)
          ## place code here rhelvm_scenario
        clear
scenario_rhvm=(
'Basic RHVM Scenarios (1-10)

1 Scenario: A VM in RHVM is not starting. How do you troubleshoot

✔ Answer:

 Check available host resources (CPU, RAM, storage), verify the VM status in RHVM Manager, ensure disk attachment, and analyze logs using journalctl -xe or /var/log/ovirt-engine/'

'2 Scenario: You need to migrate a running VM to another RHVM host without downtime. What method do you use

✔ Answer:

 Use Live Migration from RHVM, which allows VM migration without interrupting service'

'3 Scenario: A VM is running out of disk space. How do you increase its disk size

✔ Answer:

 Shut down the VM, expand the disk in RHVM under Disks, then resize the filesystem inside the guest OS'

'4 Scenario: A VM is consuming excessive CPU. How do you limit it

✔ Answer:

 Configure CPU Pinning or CPU Quota within RHVM settings'

'5 Scenario: How do you take a VM snapshot in RHVM

✔ Answer:

 Go to Compute → Virtual Machines, select the VM, navigate to Snapshots, and create a snapshot'

'6 Scenario: A user accidentally deleted a VM. How do you recover it

✔ Answer:

 Restore from VM snapshots or RHVM backups if available. If the disk exists, create a new VM and attach the disk'

'7 Scenario: How do you automate VM provisioning in RHVM

✔ Answer:

 Use Ansible RHVM modules or the oVirt REST API'

'8 Scenario: You need to move a VM to another storage domain. How do you do it

✔ Answer:

 Perform Live Storage Migration in RHVM Manager'

'9 Scenario: A VM suddenly loses network connectivity. How do you troubleshoot

✔ Answer:

 Check NIC status, verify network settings, restart NetworkManager, and analyze logs in /var/log/messages'

'10 Scenario: A host running RHVM crashes. What happens to its VMs

✔ Answer:

 If High Availability (HA) is enabled, VMs restart on another host. Otherwise, they stay down until manually started elsewhere'

'Networking Scenarios (11-20)

11 Scenario: You need to isolate VM traffic on different VLANs. What RHVM feature do you use

✔ Answer:

 Use Logical Networks with VLAN tagging and assign VLAN IDs to VM interfaces'

'12 Scenario: A VM requires a dedicated physical network adapter. How do you configure it

✔ Answer:

 Use PCI Passthrough or SR-IOV (Single Root I/O Virtualization)'

'13 Scenario: How do you enable DHCP services for VMs

✔ Answer:

 Configure Logical Networks with a DHCP server or set up PXE booting'

'14 Scenario: A VM requires network redundancy. What’s the best approach

✔ Answer:

 Configure NIC bonding or assign multiple virtual NICs connected to different networks'

'15 Scenario: A VM needs an isolated private network. How do you achieve this

✔ Answer:

 Create an isolated Logical Network within RHVM'

'16 Scenario: How do you troubleshoot a VM with no external network access

✔ Answer:

 Check RHVM network configuration, verify VM IP settings, and test using ping and traceroute'

'17 Scenario: How do you configure RHVM to allow VM traffic through a VPN

✔ Answer:

 Use NAT networking or configure VPN passthrough'

'18 Scenario: A VM needs internet access but no corporate network access. How do you configure this

✔ Answer:

 Use NAT networking with firewall rules blocking internal traffic'

'19 Scenario: How do you set up a dedicated network adapter for RHVM migration traffic

✔ Answer:

 Create a dedicated migration network in RHVM and assign it to hosts'

'20 Scenario: A VM has poor network performance. How do you troubleshoot

✔ Answer:

 Check NIC speed, enable jumbo frames, verify QoS settings, and monitor traffic with iftop'

'Storage & Disaster Recovery Scenarios (21-30)

21 Scenario: A VM’s disk usage is increasing rapidly. How do you manage it

✔ Answer:

 Convert to thin provisioning, enable storage deduplication, and monitor growth'

'22 Scenario: How do you migrate a VM from an old RHVM cluster to a new one

✔ Answer:

 Use Export Domains or RHVM Backup & Restore'

'23 Scenario: You need a VM template for faster deployment. How do you create one

✔ Answer:

 Create a Template in RHVM and deploy VMs from it'

'24 Scenario: A storage domain is running out of space. How do you handle this

✔ Answer:

 Expand storage, delete old snapshots, or migrate VMs to another domain'

'25 Scenario: A VM snapshot won’t delete. How do you fix it

✔ Answer:

 Manually merge snapshots using qemu-img or restart the RHVM Engine'

'26 Scenario: How do you ensure a VM is highly available

✔ Answer:

 Enable High Availability (HA) in VM settings'

'27 Scenario: What happens if an RHVM storage domain fails

✔ Answer:

 If storage redundancy is not configured, VMs will stop. If replication is enabled, failover occurs'

'28 Scenario: How do you set up offsite disaster recovery for RHVM

✔ Answer:

 Use Geo-Replication or oVirt Backup'

'29 Scenario: A VM backup failed. How do you troubleshoot

✔ Answer:

 Check backup logs, verify storage availability, and restart the backup service'

'30 Scenario: How do you recover a deleted VM

✔ Answer:

 Restore from RHVM Backup or manually attach the disk to a new VM'

'Advanced RHVM Scenarios (31-50)

31 Scenario: How do you monitor RHVM performance

✔ Answer:

 Use RHVM Metrics, Grafana, and ovirt-engine logs'

'32 Scenario: A VM needs more RAM without rebooting. What feature do you use

✔ Answer:

 Use Memory Hot-Add if supported'

'33 Scenario: How do you protect RHVM against ransomware

✔ Answer:

 Enable snapshots, backups, and enforce RBAC security policies'

'34 Scenario: How do you test an RHVM HA failover scenario

✔ Answer:

 Manually shut down a host and check if VMs restart on another node'

'35 Scenario: A VM takes too long to boot. What do you check

✔ Answer:

 Analyze boot logs, check disk performance, and optimize startup services'

'36 Scenario: How do you configure RHVM to send alerts

✔ Answer:

 Use RHVM Engine Notifications and configure SNMP traps'

'37 Scenario: You need to migrate a large number of VMs. What’s the best approach

✔ Answer:

 Use Ansible Playbooks or RHVM Automation API'

'38 Scenario: How do you configure RHVM for PCI Passthrough

✔ Answer:

 Enable VT-d (Intel) or AMD-Vi in BIOS, configure Host Device Passthrough in RHVM'

'39 Scenario: A VM must have minimal downtime during patching. What’s the best practice

✔ Answer:

 Use Live Migration to move the VM before host maintenance'

'40 Scenario: A VM needs GPU acceleration. How do you configure this

✔ Answer:

 Use vGPU Passthrough with PCI Passthrough settings'
)


last_index=$((${#scenario_rhvm[@]} - 1 ))
Total_questions="40"
echo " Total questions:$Total_questions"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_rhvm[$i]}"
        echo " "
        echo " "
         echo " "
          echo " "
           echo " "
            echo " "
             echo " "
              echo " "
        read -p "Press Enter key to continue "
        clear
        echo " Total 40 questions"
        echo " "
done
clear
echo " End of questions. Thanks for participating"

        ;;

  c)
      

rhvm_quiz=(
"What is the primary function of Red Hat Virtualization Manager (RHVM)?|a) Managing physical servers|b) Managing and orchestrating virtual machines|c) Configuring firewalls|d) Managing Kubernetes clusters|b"
"Which hypervisor is primarily used in Red Hat Virtualization (RHV)?|a) VMware ESXi|b) Microsoft Hyper-V|c) Kernel-based Virtual Machine (KVM)|d) Xen|c"
"What database does RHVM use for storing configuration and metadata?|a) MySQL|b) PostgreSQL|c) SQLite|d) Oracle DB|b"
"Which protocol does RHVM use for remote management?|a) SSH|b) RDP|c) VNC|d) REST API|d"
"RHVM provides a web-based management interface called?|a) RHV Console|b) Admin Portal|c) vSphere Client|d) Virt-Manager|b"
"What is the default port used by RHVM for web access?|a) 80|b) 8080|c) 443|d) 8443|d"
"During RHVM installation, which command is used to configure the manager?|a) setup-rhvm|b) ovirt-engine-setup|c) rhvm-configure|d) rhv-installer|b"
"Which package provides the RHVM engine service?|a) rhvm-engine|b) ovirt-engine|c) kvm-manager|d) rhv-mgr|b"
"What is the default storage domain type required for RHVM?|a) NFS|b) iSCSI|c) GlusterFS|d) Local storage|a"
"Which command checks the status of RHVM services?|a) systemctl status ovirt-engine|b) service ovirt-engine status|c) rhvmctl status|d) engine-status|a"
"How can you create a virtual machine in RHVM?|a) Using the Admin Portal|b) Using the REST API|c) Using virt-install|d) All of the above|d"
"What is the default console protocol for accessing RHV virtual machines?|a) RDP|b) SPICE|c) VNC|d) SSH|b"
"What is a 'template' in RHVM?|a) A predefined virtual machine configuration|b) A backup copy of a VM|c) A storage volume|d) A networking policy|a"
"Which feature allows RHVM to schedule automatic VM startup and shutdown?|a) VM Scheduling|b) High Availability (HA)|c) Power Management|d) Auto Scaling|b"
"What is the role of the 'quota' feature in RHVM?|a) Limits the number of VMs per user|b) Controls resource allocation per user or group|c) Defines network bandwidth limits|d) Manages backup retention|b"
"What is the default network type in RHVM?|a) NAT|b) Bridged|c) Routed|d) Isolated|b"
"Which network component in RHVM provides VLAN tagging?|a) Logical Switch|b) Virtual NIC|c) Network Profile|d) Logical Network|d"
"What is a 'bonded network' in RHVM?|a) A network with multiple IPs|b) A network with aggregated physical interfaces|c) A network using only IPv6|d) A VPN-based network|b"
"Which RHVM feature ensures network traffic is isolated between VMs?|a) VLAN tagging|b) Firewall rules|c) Network bonding|d) Storage Domains|a"
"What is the purpose of the oVirt Network Provider for OpenStack?|a) Integrates RHVM with OpenStack networking|b) Configures physical routers|c) Provides firewall services|d) Manages cloud storage|a"
"What are the three types of storage domains in RHVM?|a) ISO, Data, and Export|b) Block, Object, and File|c) Local, Remote, and Hybrid|d) Primary, Secondary, and Backup|a"
"Which protocol does RHVM support for shared storage?|a) NFS|b) iSCSI|c) GlusterFS|d) All of the above|d"
"What is a storage pool in RHVM?|a) A logical collection of storage domains|b) A backup repository|c) A redundant storage system|d) A virtual disk format|a"
"What is the default format for virtual machine disks in RHVM?|a) VMDK|b) QCOW2|c) RAW|d) VDI|b"
"What is Live Storage Migration in RHVM?|a) Moving a VM's disk from one storage domain to another without downtime|b) Backing up VM disks|c) Copying data between datacenters|d) Mirroring storage volumes|a"
"Which authentication method does RHVM support by default?|a) RADIUS|b) Kerberos|c) LDAP|d) Local database authentication|c"
"In RHVM, which role has full administrative privileges?|a) Cluster Administrator|b) Data Center Administrator|c) SuperUser|d) System Administrator|b"
"What is SELinux's default mode in RHV hosts?|a) Disabled|b) Permissive|c) Enforcing|d) Monitoring|c"
"How can an administrator assign permissions to users in RHVM?|a) Using the REST API|b) Using the Admin Portal|c) Using the ovirt-engine command-line|d) All of the above|d"
"What is the primary purpose of TLS in RHVM?|a) Secure web console access|b) Encrypt VM network traffic|c) Encrypt storage access|d) Secure database communication|a"
"Which built-in tool does RHVM use for performance monitoring?|a) Grafana|b) Collectd|c) Gluster Metrics|d) Data Warehouse|d"
"What is the default logging location for RHVM?|a) /var/log/ovirt-engine/|b) /etc/ovirt-engine/logs/|c) /var/lib/ovirt/logs/|d) /opt/rhv/logs/|a"
"How can you monitor real-time VM resource usage in RHVM?|a) Using the VM Portal|b) Using Data Warehouse reports|c) Using the Admin Portal|d) All of the above|d"
"What is the purpose of the RHV-M metrics store?|a) Stores historical performance data|b) Tracks VM migrations|c) Stores VM snapshots|d) Provides database backup|a"
"Which command is used to check the health status of an RHV environment?|a) ovirt-engine-status|b) rhv-healthcheck|c) ovirt-engine-check|d) ovirt-metrics|a"
"What feature ensures a VM restarts on another host in case of failure?|a) Load Balancing|b) Cluster Migration|c) High Availability (HA)|d) Failover Manager|c"
"What is the role of the Hosted Engine in RHVM?|a) Runs RHVM as a virtual machine on RHV itself|b) Manages backup operations|c) Acts as a secondary hypervisor|d) Provides a secondary storage domain|a"
"How does RHVM handle host failures?|a) Automatically restarts VMs on another available host|b) Sends an alert and keeps VMs off|c) Restores VMs from backup|d) Pauses VMs until the administrator intervenes|a"
"What is the purpose of fencing in RHVM?|a) Isolates failed hosts from the cluster|b) Prevents unauthorized access|c) Limits VM resource usage|d) Disconnects unresponsive storage|a"
"Which method does RHVM use to prevent split-brain scenarios in clusters?|a) Heartbeat detection|b) VM migration|c) Network fencing|d) Storage replication|a"
"What is the difference between live migration and cold migration?|a) Live migration moves a running VM; cold migration moves a stopped VM|b) Live migration moves VMs across data centers; cold migration moves VMs within a cluster|c) Live migration copies VM data; cold migration clones VMs|d) They are the same process|a"
"How can you revert a VM to a previous state in RHVM?|a) Using a snapshot|b) Restoring from a backup|c) Using a template|d) Restarting the VM|a"
"What happens when a storage domain runs out of space?|a) VM disks become read-only|b) VMs automatically pause|c) New VMs cannot be created|d) All of the above|d"
"How does RHVM handle storage domain failures?|a) Automatically switches to a secondary storage domain|b) Stops all running VMs|c) Restarts the storage service|d) Migrates data to local storage|a"
"What is the purpose of an ISO storage domain?|a) Stores VM installation media|b) Acts as a backup repository|c) Manages cloud-based storage|d) Encrypts storage traffic|a"
"How can you troubleshoot RHVM if the web portal is inaccessible?|a) Restart the ovirt-engine service|b) Check firewall settings|c) Verify PostgreSQL database status|d) All of the above|d"
"Which RHVM feature allows VMs to use more RAM than physically available?|a) Memory Ballooning|b) Virtual NUMA|c) Transparent Huge Pages|d) RAM Overcommit|a"
"Which tool helps automate RHVM deployment using scripts?|a) Ansible|b) Puppet|c) Terraform|d) All of the above|d"
"How does RHVM integrate with Red Hat Ansible?|a) Automates VM and host configuration|b) Manages network security|c) Monitors cluster health|d) Provides API security|a"
"What is the role of the 'ovirt-imageio' service in RHVM?|a) Transfers disk images between storage domains|b) Monitors VM performance|c) Configures firewall rules|d) Manages cluster authentication|a"
)

SCORE=0
TOTAL_QUESTIONS=${#rhvm_quiz[@]}

clear
echo "================================="
echo "🔥 Rhel VM Manager MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!rhvm_quiz[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${rhvm_quiz[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
         read -p "Press ENTER key to move to the next question"
         clear
    fi

     done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing RHVM MCQ! 🚀"
;;
0) break ;;
*) echo "Invalid option. Try again." ;;
esac
done
;;
0) break ;;
*) echo "Invalid option. Try again.";;

 esac

 done

 ;;

  3)
     while true; do
     echo " You have selected Windows Environment topic"

     echo " "
     echo " "
     echo "  i) MECM"
     echo " ii) Powershell"
     echo "iii) Windows server"
     echo " iv) Microsoft O365" 
     echo "  0) Back to the main menu"
     read -p "select skill:🎯 " skill_win
     clear
     case $skill_win in
 i)
     while true; do
     echo " You selected MECM skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " MECM_way
     case $MECM_way in
 a)
       clear
# Array of questions
mecm_questions=(
'# MECM Interview Questions

1. What is MECM?

Answer:

        MECM (Microsoft Endpoint Configuration Manager) is a management tool used to deploy, update, and secure Windows devices across an organization.'
'2. What are the key features of MECM?

Answer:

       Software deployment, OS deployment, patch management, inventory management, and endpoint security.'
'3. How do you install the MECM client manually?

Answer:

      Run the following command on the client machine:
      \\\\MECMServer\\SMS_\\Client\setup.exe /mp:MECMServer FSP=MECMServer SMSSITECODE=ABC'
'4. How do you check if the MECM client is installed?

Answer:

      Open Control Panel -> Configuration Manager -> General tab.'
'5. What is a Distribution Point in MECM?

Answer:

      A Distribution Point (DP) is a server that stores content for software packages, updates, and OS deployments.'
'6. How do you deploy an application in MECM?

Answer:

      MECM Console -> Software Library -> Applications -> Create Application -> Deploy to Device Collection.'
'7. How do you force a client policy update in MECM?

Answer:

      Open Configuration Manager Properties -> Actions Tab -> Run "Machine Policy Retrieval & Evaluation Cycle".'
'8. How do you troubleshoot client installation issues?

Answer:

      Check logs like ccmsetup.log, ClientIDManagerStartup.log, and PolicyAgent.log on the client machine.'
'9. How do you create a task sequence in MECM?

Answer:

      MECM Console -> Software Library -> Operating System -> Task Sequences -> Create Task Sequence.'
'10. What is a Boundary and Boundary Group in MECM?

Answer:

      Boundaries define network locations for clients, while Boundary Groups associate boundaries with content locations.'
'11. What is the Site Server in MECM?

Answer:

      The Site Server is the primary server that manages and deploys configurations to clients.'
'12. What is the Software Center in MECM?

Answer:

      Software Center is a client application where users can install available applications and updates.'
'13. How do you monitor software deployment status?

Answer:

      MECM Console -> Monitoring -> Deployments -> View Status.'
'14. How do you configure WSUS in MECM?

Answer:

      Install WSUS role, configure SUP in MECM, and sync updates.'
'15. What is CMPivot in MECM?

Answer:

      CMPivot allows real-time querying of client data for troubleshooting and compliance.'
'16. How do you check the SCCM client version?

Answer:

      Run "Configuration Manager Properties" -> General tab.'
'17. How do you configure compliance settings in MECM?

Answer:

      MECM Console -> Assets and Compliance -> Compliance Settings -> Create Configuration Item.'
'18. How do you enable PXE boot in MECM?

Answer:

      Enable PXE support on Distribution Point settings.'
'19. How do you configure BitLocker management in MECM?

Answer:

      Enable BitLocker policies under Endpoint Protection settings.'
'20. How do you deploy Office 365 using MECM?

Answer:

      Use Office Deployment Tool (ODT) with MECM application deployment.'
)

last_index=$(( ${#mecm_questions[@]} - 1 ))
Total_questions="${#mecm_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${mecm_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

       
        ;;

  b)
         
       clear

scenario_mecm=(

'Basic MECM Scenarios (1-10)

1 Scenario: A client is not receiving software updates from MECM. How do you troubleshoot?

✔ Answer:

Check if the client is active in MECM, verify the WSUS/SUP configuration, review WUAHandler.log on the client, and ensure boundary groups are correctly configured.'

'2 Scenario: How do you deploy software using MECM?

✔ Answer:

Create an application or package in MECM, distribute it to the distribution points, and deploy it to a collection of targeted devices.'

'3 Scenario: A software deployment is stuck at "Waiting to Install." How do you resolve it?

✔ Answer:

Check the AppEnforce.log and PolicyAgent.log, verify deployment settings, and ensure the client has received the policy.'

'4 Scenario: A device is not appearing in MECM. What troubleshooting steps do you take?
✔ Answer:

Check if the SCCM client is installed, verify network connectivity, review ClientIDManagerStartup.log, and ensure Active Directory discovery is working.'

'5 Scenario: How do you check if the MECM client is communicating with the management point?

✔ Answer:

Review the ClientLocation.log, LocationServices.log, and confirm connectivity to the management point.'

'6 Scenario: A software update deployment is failing. How do you troubleshoot?

✔ Answer:

Review UpdatesDeployment.log, UpdatesHandler.log, and WUAHandler.log on the client, and verify WSUS synchronization in MECM.'

'7 Scenario: How do you configure Boundary Groups in MECM?

✔ Answer:

Navigate to Administration > Hierarchy Configuration > Boundary Groups, assign site roles, and ensure clients are mapped correctly.'

'8 Scenario: A package is not being distributed to a distribution point. What do you check?

✔ Answer:

Review PkgXferMgr.log, ensure the DP has enough storage, check for network connectivity issues, and verify package status in MECM.'

'9 Scenario: How do you force a client to check for new policies?

✔ Answer:

Use the Configuration Manager client under "Actions," run the Machine Policy Retrieval & Evaluation Cycle, or use PowerShell.'

'10 Scenario: How do you initiate a remote control session in MECM?

✔ Answer:

Go to the MECM console, select the client device, and use the "Remote Control" option under the "Device" menu.'

'Operating System Deployment (11-20)

11 Scenario: A task sequence fails at the "Apply Operating System" step. How do you troubleshoot?

✔ Answer:

Check SMSTS.log for error details, verify boot image and network connectivity, and ensure correct drivers are added.'

'12 Scenario: How do you capture an image for deployment in MECM?

✔ Answer:

Use the "Capture Media" wizard, boot into WinPE, run the "Capture Image" task sequence, and upload the image to MECM.'

'13 Scenario: A PXE boot fails when deploying an OS. What do you check?

✔ Answer:

Review SMSPXE.log, ensure the distribution point supports PXE, and check DHCP options 66/67 or IP Helper settings.'

'14 Scenario: How do you deploy Windows 10 using MECM?

✔ Answer:

Create a task sequence, distribute the OS image, configure driver packages, and deploy the task sequence to a collection.'

'15 Scenario: A task sequence is stuck on "Downloading Content." How do you resolve it?

✔ Answer:

Check CAS.log, DataTransferService.log, and ensure the distribution point is accessible from the client.'

'16 Scenario: How do you deploy drivers with an OS deployment?

✔ Answer:

Use Driver Packages in MECM, assign them to the task sequence, and ensure compatibility with the target devices.'

'17 Scenario: How do you configure BitLocker during an OS deployment?

✔ Answer:

Add a "Enable BitLocker" step in the task sequence and configure TPM settings via Group Policy.'

'18 Scenario: A newly deployed system is not joining the domain. What do you check?

✔ Answer:

Verify the task sequence domain join settings, check netsetup.log, and ensure network access to the domain controller.'

'19 Scenario: How do you create a custom boot image in MECM?

✔ Answer:

Use the Windows ADK, add necessary drivers, configure WinPE settings, and distribute the boot image to DPs.'

'20 Scenario: A task sequence fails with error 0x80070002. How do you troubleshoot?

✔ Answer:

Review SMSTS.log, check for missing package references, and ensure the content is available on distribution points.'

'Software Updates & Compliance (21-30)

21 Scenario: How do you deploy Windows updates in MECM?

✔ Answer:

Synchronize WSUS, create a Software Update Group, distribute content, and deploy it to a collection.'

'22 Scenario: A client is not installing updates. How do you troubleshoot?

✔ Answer:

Check WUAHandler.log, UpdatesDeployment.log, and ensure SUP synchronization is working properly.'

'23 Scenario: How do you configure automatic update deployment?

✔ Answer:

Use Automatic Deployment Rules (ADR) in MECM to schedule and deploy updates automatically.'

'24 Scenario: How do you enforce compliance settings in MECM?

✔ Answer:

Use Configuration Items and Baselines, deploy them to a collection, and monitor compliance reports.'

'25 Scenario: A device is marked as "Non-Compliant" in a baseline. What do you check?

✔ Answer:

Review DcmWmiProvider.log, verify the compliance item settings, and ensure proper remediation rules.'

'26 Scenario: How do you deploy security patches in MECM?

✔ Answer:

Use Software Updates, create a deployment package, and assign it to the target collection.'

'27 Scenario: What logs help troubleshoot update failures?

✔ Answer:

WUAHandler.log, UpdatesDeployment.log, UpdatesHandler.log, and WindowsUpdate.log.'

'28 Scenario: How do you manage third-party updates in MECM?

✔ Answer:

Enable third-party updates in Software Update Point settings and use SCUP (System Center Updates Publisher).'

'29 Scenario: How do you configure Windows 11 upgrade through MECM?

✔ Answer:

Use Feature Updates via Windows Servicing or create an in-place upgrade task sequence.'

'30 Scenario: How do you verify that a client has applied a deployed update?

✔ Answer:

Check WMI query results, review update logs, and confirm status in the MECM console.'

'MECM Administration & Infrastructure (31-40)

31 Scenario: How do you monitor MECM infrastructure health?

✔ Answer:

Use the Monitoring workspace in MECM, check site status, review Component Status messages, and analyze log files like SiteComp.log.'

'32 Scenario: How do you back up the MECM site database?

✔ Answer:

Use the built-in MECM Site Maintenance task or manually back up the SQL database and critical site folders.'

'33 Scenario: The MECM console is slow or unresponsive. How do you troubleshoot?

✔ Answer:

Check SQL Server performance, verify site server resources, and review SMSAdminUI.log for errors.'

'34 Scenario: How do you enable Role-Based Access Control (RBAC) in MECM?

✔ Answer:

Create custom security roles, assign permissions to user groups, and use security scopes to restrict access.'

'35 Scenario: A secondary site is not replicating with the primary site. What do you check?

✔ Answer:

Review sender.log, ReplicationManager.log, SQL Replication status, and network connectivity.'

'36 Scenario: How do you add a new Distribution Point in MECM?

✔ Answer:

Navigate to Administration > Site Configuration > Servers and Site System Roles, add a new site system, and enable Distribution Point role.'

'37 Scenario: A Management Point is not responding. How do you troubleshoot?

✔ Answer:

Check MPControl.log, IIS status, firewall settings, and verify client connections.'

'38 Scenario: How do you configure Co-Management with Intune?

✔ Answer:

Enable Co-Management in MECM, link it to Azure AD, configure workloads to shift to Intune, and monitor synchronization.'

'39 Scenario: A Cloud Management Gateway (CMG) is not connecting. How do you fix it?

✔ Answer:

Verify CMG certificates, check CMGService.log, ensure correct firewall settings, and confirm Azure subscription validity.'

'40 Scenario: How do you migrate from MECM to Microsoft Intune?

✔ Answer:

Use Co-Management for a phased migration, move workloads gradually, and reconfigure policies in Intune.'

'Application Deployment & Troubleshooting (41-50)

41 Scenario: How do you package and deploy a custom application in MECM?

✔ Answer:

Create an Application, define detection rules, distribute content to Distribution Points, and deploy it to a device collection.'

'42 Scenario: A deployed application is not installing on clients. How do you troubleshoot?

✔ Answer:

Check AppEnforce.log, verify deployment settings, and ensure the application content is available on DPs.'

'43 Scenario: How do you create a dynamic application deployment in MECM?

✔ Answer:

Use requirement rules, Global Conditions, and user-based targeting to deploy applications dynamically.'

'44 Scenario: How do you configure dependencies for an application?

✔ Answer:

Define application dependencies within the MECM Application model before deployment.'

'45 Scenario: How do you deploy scripts using MECM?

✔ Answer:

Use the Scripts feature in the MECM console, create a PowerShell script, approve it, and deploy it to devices.'

'46 Scenario: How do you force a client to install an application immediately?

✔ Answer:

Trigger "Application Deployment Evaluation Cycle" from MECM client actions or use PowerShell commands.'

'47 Scenario: How do you track software metering in MECM?

✔ Answer:

Enable Software Metering in MECM, configure rules, and generate reports to monitor software usage.'

'48 Scenario: How do you remove an application from multiple devices using MECM?

✔ Answer:

Create an "Uninstall" deployment for the application and target the required collection.'

'49 Scenario: How do you deploy Microsoft 365 Apps using MECM?

✔ Answer:

Use the Office 365 Client Installation wizard, specify the configuration, and deploy it to a collection.'

'50 Scenario: How do you check the deployment status of an application?

✔ Answer:

Go to Monitoring > Deployments in MECM, check status messages, and review client logs (AppEnforce.log, PolicyAgent.log).'

)


last_index=$(( ${#scenario_mecm[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_mecm[$i]}"
        echo " "
        echo ""
        echo ""
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press enter key to continue..."
        clear
        echo ' Total 50 questions'
done
clear
echo " End of questions. Thanks for participating"

        ;;

  c)
       
# Define MCQs with options and answers
QUESTIONS=(
    "What is MEMCM?|a) A cloud-based management tool|b) A configuration management tool for Windows|c) A Linux-only deployment system|d) A security software|b"
    "What is the main function of MEMCM?|a) Software deployment and management|b) Web development|c) Cloud storage|d) Data analytics|a"
    "Which component is responsible for deploying applications in MEMCM?|a) Distribution Point|b) Management Point|c) Software Update Point|d) Reporting Services|a"
    "What is the purpose of a Distribution Point in MEMCM?|a) To distribute content to clients|b) To store database logs|c) To configure user settings|d) To analyze network traffic|a"
    "Which protocol does MEMCM use to communicate with clients?|a) HTTP/HTTPS|b) FTP|c) SMTP|d) ICMP|a"
    "How can you manually install the MEMCM client on a device?|a) Through Windows Update|b) Using \"ccmsetup.exe\"|c) By enabling Remote Desktop|d) Through Registry Editor|b"
    "Which log file helps troubleshoot MEMCM client installation issues?|a) ccmsetup.log|b) WindowsUpdate.log|c) SCCM.log|d) EventViewer.log|a"
    "Which database does MEMCM use by default?|a) MySQL|b) PostgreSQL|c) Microsoft SQL Server|d) MongoDB|c"
    "Which MEMCM feature allows operating system deployment?|a) Software Center|b) Task Sequences|c) Compliance Settings|d) Role-Based Access Control|b"
    "What is the purpose of Software Center in MEMCM?|a) To allow users to install approved applications|b) To manage network configurations|c) To create task sequences|d) To configure SQL databases|a"
    "Which component stores hardware and software inventory data in MEMCM?|a) Reporting Services|b) SQL Database|c) Inventory Agent|d) Site Server|c"
    "Which MEMCM feature allows patching of Windows systems?|a) Endpoint Protection|b) Software Updates|c) Operating System Deployment|d) Asset Intelligence|b"
    "What is the purpose of a Management Point in MEMCM?|a) To store MEMCM configuration settings|b) To facilitate communication between clients and servers|c) To distribute updates|d) To monitor server health|b"
    "How do you force a client policy update in MEMCM?|a) Restart the computer|b) Run \"Machine Policy Retrieval & Evaluation Cycle\"|c) Delete the client cache|d) Reset the device|b"
    "What is the default port for MEMCM client communication over HTTPS?|a) 443|b) 80|c) 8080|d) 22|a"
    "Which MEMCM tool helps analyze log files?|a) ConfigMgr Console|b) Event Viewer|c) CMTrace|d) PowerShell|c"
    "What is the purpose of Role-Based Administration in MEMCM?|a) To provide access based on user roles|b) To restrict internet access|c) To enforce group policies|d) To monitor network performance|a"
    "Which feature helps in reporting compliance in MEMCM?|a) SQL Server Reporting Services (SSRS)|b) Active Directory|c) Network Discovery|d) Endpoint Protection|a"
    "Which MEMCM role is required for Endpoint Protection?|a) Management Point|b) Software Update Point|c) Fallback Status Point|d) State Migration Point|b"
    "How do you check if a client is communicating with MEMCM?|a) Check Configuration Manager properties|b) Restart the client machine|c) Disable firewall settings|d) Check Event Viewer|a"
    "What is the purpose of Compliance Settings in MEMCM?|a) To enforce security policies|b) To deploy updates|c) To manage software installations|d) To monitor log files|a"
    "Which feature enables MEMCM integration with Intune?|a) Co-Management|b) Active Directory Sync|c) Windows Deployment Services|d) BitLocker Management|a"
    "Which MEMCM log file records site server activities?|a) Sitecomp.log|b) ccmsetup.log|c) PolicyAgent.log|d) WUAHandler.log|a"
    "Which of the following is NOT a deployment method in MEMCM?|a) Available|b) Required|c) Manual|d) Optional|c"
    "Which MEMCM feature provides real-time client information?|a) Client Notification|b) Asset Intelligence|c) Endpoint Protection|d) Task Sequences|a"
    "Which component is used for remote control of MEMCM clients?|a) Remote Desktop|b) Remote Control|c) VNC Viewer|d) TeamViewer|b"
    "How do you remove an application from all MEMCM clients?|a) Disable the application in Software Center|b) Delete the application from the console|c) Create an uninstall deployment|d) Restart the clients|c"
    "What is the main purpose of Maintenance Windows in MEMCM?|a) To schedule updates and installations|b) To prevent users from accessing MEMCM|c) To clean up old logs|d) To optimize network performance|a"
    "Which MEMCM feature allows BitLocker encryption management?|a) BitLocker Management|b) Endpoint Protection|c) Compliance Settings|d) Remote Control|a"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 MEMCM MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering MEMCM! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;

esac
done
    ;;


    ii)
     while true; do
     echo " You selected Powershell skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " powershell_way
     case $powershell_way in
 a)
        
	 clear

questions_powershell=(
'# Basics of PowerShell (1-10)

1. What is PowerShell?

Answer:

PowerShell is a command-line shell and scripting language built on .NET, designed for automation and configuration management in Windows.'

'2. How is PowerShell different from Command Prompt (CMD)?

Answer:

Feature PowerShell      Command Prompt
Scripting Language      Yes     No
Object-Oriented Yes     No
Supports .NET   Yes     No
Advanced Automation     Yes     No'

'3. How do you check the PowerShell version?

Answer:

$PSVersionTable.PSVersion'

'4. What is the execution policy in PowerShell?

Answer:

The execution policy determines whether scripts can run. Common policies:

Restricted (default) – No scripts allowed.
RemoteSigned – Locally created scripts run, downloaded scripts need a signature.
Unrestricted – All scripts can run.
Set Execution Policy:

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser'

'5. How do you list all available PowerShell commands?

Answer:

Get-Command'

'6. How do you get help for a command?

Answer:

Get-Help Get-Process'

'7. How do you find all cmdlets related to "service"?

Answer:

Get-Command *service*'

'8. How do you check all running services using PowerShell?

Answer:

Get-Service | Where-Object { $_.Status -eq "Running" }'

'9. How do you find all processes running on a system?

Answer:

Get-Process'

'10. How do you stop a process by name?

Answer:

Stop-Process -Name notepad -Force'

'11. How do you declare and use a variable in PowerShell?

Answer:

$greeting = "Hello, PowerShell!"
Write-Output $greeting'

'12. How do you take user input in PowerShell?

Answer:

$name = Read-Host "Enter your name"
Write-Output "Hello, $name!"'

'13. How do you define a function in PowerShell?

Answer:

function Say-Hello {
    param($name)
    Write-Output "Hello, $name!"
}
Say-Hello -name "John"'

'14. What is the difference between a script and a function in PowerShell?

Answer:

Feature    Script    Function
Scope      Runs in global scope    Local scope by default
Calling    Runs as a separate file    Runs within a script'

'15. How do you pass parameters to a script?

Answer:

Create a script script.ps1:

param($name)
Write-Output "Hello, $name!"

Run:

.\script.ps1 -name "John"'

'16. How do you loop through an array in PowerShell?

Answer:

$names = @("Alice", "Bob", "Charlie")
foreach ($name in $names) {
    Write-Output "Hello, $name!"
}'

'17. How do you create a scheduled task using PowerShell?

Answer:

$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -TaskName "OpenNotepad" -Action $action -Trigger $trigger'

'18. How do you write output to a file in PowerShell?

Answer:

"Hello, PowerShell!" | Out-File -FilePath "C:\output.txt"'

'19. How do you read a file in PowerShell?

Answer:

Get-Content -Path "C:\output.txt"'

'20. How do you test if a file exists in PowerShell?

Answer:

Test-Path "C:\output.txt"'

'# System Administration

21. How do you get all installed software on a system?

Answer:

Get-WmiObject -Class Win32_Product'

'22. How do you get a list of all local users on a system?

Answer:

Get-LocalUser'

'23. How do you get system information using PowerShell?

Answer:

Get-ComputerInfo'

'24. How do you restart a remote computer?

Answer:

Restart-Computer -ComputerName "RemotePC" -Force'

'25. How do you change the IP address using PowerShell?

Answer:

New-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1'

'# Active Directory

31. How do you get all users in Active Directory?

Answer:

Get-ADUser -Filter *'

'32. How do you reset a users password in Active Directory?

Answer:

Set-ADAccountPassword -Identity "UserName" -NewPassword (ConvertTo-SecureString "NewPass123" -AsPlainText -Force)'

'33. How do you unlock a locked-out user in AD?

Answer:

Unlock-ADAccount -Identity "UserName"'

'34. How do you get all groups a user belongs to?

Answer:

Get-ADUser -Identity "UserName" -Properties MemberOf | Select-Object -ExpandProperty MemberOf'

'# Security & Compliance

41. How do you check for open ports on a computer?

Answer:

Get-NetTCPConnection | Select-Object LocalPort, State'

'42. How do you list all firewall rules?

Answer:

Get-NetFirewallRule'

'43. How do you disable a user account in Active Directory?

Answer:

Disable-ADAccount -Identity "UserName"'

'44. How do you get failed login attempts on a server?

Answer:

Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4625 } | Select-Object TimeGenerated, Message'
)

last_index=$(( ${#questions_powershell[@]} - 1 ))
Total_questions="44"
echo " Total questions:$Total_questions"
echo " Lets practice linux scenario based interview questions and answers"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${questions_powershell[$i]}"
        echo " "
        read -p ""
        clear
        echo ' Total 44 questions
 Press Enter key to clear the screen & move to the next question !'
done
clear
echo " Good ! You visited all questions and answers"
        

        ;;

  b)
        
       
clear

scenario_powershell=(

'1. Scenario: You need to run a PowerShell script, but it wont execute. How do you fix it?

Answer:

Check the execution policy:

Get-ExecutionPolicy

Change it if needed:

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser'

'2. Scenario: You need to pass arguments to a PowerShell script. How do you do it?

Answer:

Create script.ps1:

param($name, $age)
Write-Output "Name: $name, Age: $age"

Run it:

.\script.ps1 -name "John" -age 30'

'3. Scenario: You need to check if a file exists before performing an operation.

Answer:

if (Test-Path "C:\data.txt") {
Write-Output "File exists."
} else {
Write-Output "File does not exist."
}'

'4. Scenario: You want to output data to both the console and a file simultaneously.

Answer:

"Logging this message" | Tee-Object -FilePath "C:\log.txt"'

'5. Scenario: You need to schedule a PowerShell script to run daily.

Answer:

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\scripts\backup.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "DailyBackup" -Action $action -Trigger $trigger'

'6. Scenario: You need to find all running processes consuming high CPU usage.

Answer:

Get-Process | Sort-Object CPU -Descending | Select-Object -First 10'

'7. Scenario: You need to restart a remote computer.

Answer:

Restart-Computer -ComputerName "RemotePC" -Force'

'8. Scenario: You need to modify the IP address of a network adapter.

Answer:

New-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1'

'9. Scenario: You need to find the system uptime.

Answer:

(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime'

'10. Scenario: You need to clear all event logs on a Windows system.

Answer:

wevtutil el | Foreach-Object { wevtutil cl $_ }'

'11. Scenario: You need to get a list of all Active Directory users.

Answer:

Get-ADUser -Filter *'

'12. Scenario: You need to reset a users password in Active Directory.

Answer:

Set-ADAccountPassword -Identity "jdoe" -NewPassword (ConvertTo-SecureString "NewPass123" -AsPlainText -Force)'

'13. Scenario: You need to find all disabled user accounts in Active Directory.

Answer:

Get-ADUser -Filter {Enabled -eq $false}'

'14. Scenario: You need to unlock a locked-out user in Active Directory.

Answer:

Unlock-ADAccount -Identity "jdoe"'

'15. Scenario: You need to check when a user last logged in.

Answer:

Get-ADUser -Identity "jdoe" -Properties LastLogonDate'

'16. Scenario: You need to check for failed login attempts on a server.

Answer:

Get-EventLog -LogName Security -InstanceId 4625 -Newest 10'

'17. Scenario: You need to get all local user accounts on a system.

Answer:

Get-LocalUser'

'18. Scenario: You need to enable BitLocker on a drive.

Answer:

Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector'

'19. Scenario: You need to export all installed Windows updates.

Answer:

Get-HotFix | Export-Csv "C:\updates.csv" -NoTypeInformation'

'20. Scenario: You need to check all open network ports.

Answer:

Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }'

'21. Scenario: You need to automate the installation of software using PowerShell.

Answer:

Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\install.msi'


'22 Scenario: You need to automate user creation in Active Directory.

Answer:

New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com" -PasswordNeverExpires $true -Enabled $true.'

'23 Scenario: You need to run PowerShell commands on a remote machine.

Answer:

Invoke-Command -ComputerName "RemotePC" -ScriptBlock { Get-Service }.'

'24 Scenario: You need to retrieve disk space usage for all drives.

Answer:

Get-PSDrive -PSProvider FileSystem.'

'25 Scenario: You need to get the list of running services.

Answer:

Get-Service | Where-Object { $_.Status -eq "Running" }.'

'26 Scenario: You need to send an email notification using PowerShell.

Answer:

Send-MailMessage -To "user@example.com" -From "admin@example.com" -Subject "Alert" -Body "System issue detected" -SmtpServer "smtp.example.com".'

'27 Scenario: You need to fetch logs from multiple remote servers.

Answer:

$servers = @("Server1", "Server2")
foreach ($server in $servers) {
Invoke-Command -ComputerName $server -ScriptBlock { Get-EventLog -LogName System -Newest 10 }
}.'

'28 Scenario: You need to restart all services related to IIS.

Answer:

Get-Service W3SVC, WAS | Restart-Service.'
)

last_index=$(( ${#scenario_powershell[@]} - 1 ))
Total_questions="28"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_powershell[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 28 questions'
done
clear
echo " End of questions. Thanks for participating"

        ;;

  c)
        
# Define MCQs with options and answers
QUESTIONS=(
    "What is PowerShell primarily used for?|a) Web development|b) Task automation and configuration management|c) Graphic design|d) Game development|b"
    "Which command is used to get a list of all cmdlets in PowerShell?|a) Get-Command|b) Get-Help|c) Show-Commands|d) List-Cmdlets|a"
    "What is the alias for Get-ChildItem?|a) ls|b) dir|c) gci|d) All of the above|d"
    "How do you assign a value to a variable in PowerShell?|a) var x = 10|b) dollarx = 10|c) x := 10|d) int x = 10|b"
    "Which command is used to display system information?|a) systeminfo|b) Get-ComputerInfo|c) Show-System|d) Get-System|b"
    "How do you comment a single line in PowerShell?|a) // This is a comment|b) <!-- This is a comment -->|c) # This is a comment|d) -- This is a comment|c"
    "What is the output of Write-Output 'Hello'?|a) Prints 'Hello' to the console|b) Stores 'Hello' in a file|c) Sends 'Hello' to a log|d) Deletes 'Hello'|a"
    "Which cmdlet is used to read user input in PowerShell?|a) Read-Host|b) Get-Input|c) User-Read|d) Read-Variable|a"
    "What is the pipeline symbol in PowerShell?|a) ->|b) &|c) |>d) | |d"
    "Which cmdlet is used to get help for a command?|a) Get-Command|b) Get-Help|c) Show-Help|d) Help-Command|b"
    "How do you execute a PowerShell script file?|a) Run script.ps1|b) ./script.ps1|c) bash script.ps1|d) exec script.ps1|b"
    "Which command is used to list running processes?|a) Get-Services|b) Get-Processes|c) Get-Running|d) Get-Process|d"
    "What does the Get-Service cmdlet do?|a) Retrieves a list of Windows services|b) Gets network information|c) Displays disk usage|d) Installs software|a"
    "Which operator is used for comparison in PowerShell?|a) -eq|b) ==|c) =|d) equals|a"
    "Which command is used to stop a running process?|a) Stop-Process|b) End-Task|c) Kill-Task|d) Remove-Process|a"
    "How do you define a function in PowerShell?|a) function MyFunc() {}|b) def MyFunc() {}|c) MyFunc() {}|d) sub MyFunc {}|a"
    "Which command is used to check if a file exists?|a) Test-Path filename|b) Check-File filename|c) Exists filename|d) File-Exists filename|a"
    "How do you export output to a CSV file?|a) Export-Csv|b) Save-CSV|c) Write-Csv|d) Csv-Output|a"
    "What is the command to restart a computer using PowerShell?|a) Restart-Computer|b) Reboot|c) Shutdown -r|d) Power-Restart|a"
    "Which cmdlet is used to create a new item (file or directory)?|a) New-Item|b) Create-Item|c) Add-File|d) Make-Item|a"
    "How do you get the current working directory in PowerShell?|a) Get-Location|b) pwd|c) Show-Path|d) Get-Path|a"
    "Which cmdlet retrieves event logs in PowerShell?|a) Get-EventLog|b) Show-Logs|c) Retrieve-Events|d) Log-Get|a"
    "What does the -Force parameter do in PowerShell?|a) Ignores errors|b) Forces the command to execute|c) Stops execution|d) Restarts the script|b"
    "How do you list all available PowerShell modules?|a) Get-Module -ListAvailable|b) Show-Modules|c) List-Modules|d) Module-Get|a"
    "Which command is used to install a PowerShell module from the gallery?|a) Install-Module|b) Add-Module|c) Load-Module|d) Fetch-Module|a"
    "How do you check the PowerShell version?|a) dollarPSVersionTable|b) Get-Version|c) PowerShell -V|d) Check-Version|a"
    "What does Select-Object do in PowerShell?|a) Filters object properties|b) Deletes objects|c) Sorts objects|d) Renames objects|a"
    "How do you stop a script from executing?|a) exit|b) Stop-Script|c) End|d) Quit|a"
    "Which command is used to retrieve network adapter information?|a) Get-NetAdapter|b) Show-Network|c) Get-Network|d) Net-Info|a"
    "How do you delay execution in PowerShell?|a) Start-Sleep|b) Wait|c) Delay|d) Pause|a"
    "What is the cmdlet to move a file in PowerShell?|a) Move-Item|b) Transfer-File|c) Shift-File|d) Move-File|a"
    "How do you list services in PowerShell?|a) Get-Service|b) List-Services|c) Show-Services|d) Service-List|a"
    "What does -WhatIf do in PowerShell?|a) Simulates a command without executing|b) Executes a command forcefully|c) Stops execution|d) Logs the command|a"
    "Which command is used to search for text in a file?|a) Select-String|b) Find-Text|c) Search-File|d) Get-Text|a"
    "What is the command to remove an item in PowerShell?|a) Remove-Item|b) Delete-File|c) Erase|d) Unlink|a"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 PowerShell MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering PowerShell! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;

esac
done
    ;;

     iii)
     while true; do
     echo " You selected Windows server skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " winserver_way
     case $winserver_way in
 a)
        
clear

questions_windows=(

'# Active Directory (1-10)

1. What is Active Directory (AD)?

Answer:

AD is a directory service developed by Microsoft that stores information about users, computers, and resources in a network.'

'2. What are the main components of Active Directory?

Answer:

Domain – Logical group of users/computers.
Forest – Collection of domains.
Tree – Hierarchy of domains.
OU (Organizational Unit) – Used for grouping.
Schema – Defines object attributes.'

'3. How do you create a new user in Active Directory?

Answer:

Open Active Directory Users and Computers (ADUC) → Right-click Users → New → User.'

'4. What is a Domain Controller (DC)?

Answer:

A server that authenticates users and manages AD.'

'5. How do you check if a server is a Domain Controller?

Answer:

Get-ADDomainController -Filter *'

'6. What is the difference between a Domain and a Workgroup?

Answer:

Domain: Centralized management (uses AD).
Workgroup: No central management.'

'7. How do you force a Group Policy update?

Answer:

gpupdate /force'

'8. What is the SYSVOL folder in Active Directory?

Answer:

SYSVOL stores domain-wide files, scripts, and Group Policies.'

'9. How do you check Active Directory replication status?

Answer:

repadmin /replsummary'

'10. What is the purpose of FSMO roles?

Answer:

They prevent conflicts in AD by assigning specific roles to servers.'

'# Networking (11-20)

11. How do you check the IP configuration of a Windows Server?

Answer:

ipconfig /all'

'12. How do you check network connectivity?

Answer:

ping <IP/Hostname>'

'13. How do you add a static IP to a Windows Server?

Answer:

GUI: Control Panel → Network & Internet → Network Adapter → IPv4 → Properties.
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1'

'14. How do you flush the DNS cache?

Answer:

ipconfig /flushdns'

'15. How do you view the routing table?

Answer:

route print'

'16. How do you configure a Windows Server as a DHCP server?

Answer:

Install DHCP role → Configure scope → Authorize DHCP.'

'17. How do you check which ports are open on a Windows Server?

Answer:

netstat -ano'

'18. How do you test if a specific port is open on a remote server?

Answer:

Test-NetConnection -ComputerName <server> -Port <port>'

'19. What command is used to list all firewall rules?

Answer:

netsh advfirewall firewall show rule name=all'

'20. How do you disable the Windows Firewall?

Answer:

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'
'# Group Policy (21-30)

21. What is Group Policy in Windows Server?

Answer:

Group Policy allows centralized management of user and computer settings.'

'22. How do you check applied Group Policies on a machine?

Answer:

gpresult /r'

'23. How do you create a new Group Policy Object (GPO)?

Answer:

Open Group Policy Management → Right-click Domain → Create a GPO.'

'24. How do you enforce a Group Policy?

Answer:

Right-click GPO → Enforce.'

'25. How do you block Group Policy inheritance?

Answer:

Right-click OU → Block Inheritance.'

'26. How do you remove a GPO from a system?

Answer:

gpupdate /force'

'27. What is the difference between Local and Domain Group Policy?

Answer:

Local GPO – Affects only one machine.
Domain GPO – Affects multiple machines in a domain.'

'28. How do you reset all Group Policies to default?

Answer:

gpupdate /force'

'29. How do you troubleshoot Group Policy issues?

Answer:

Check Event Viewer → Logs: System & Applications.
Use gpresult /h report.html'

'30. How do you back up and restore Group Policy?

Answer:

Backup-GPO -Name "MyGPO" -Path "C:\Backup"
Restore-GPO -Name "MyGPO" -Path "C:\Backup"'

'# Security (31-40)

31. How do you check failed login attempts?

Answer:

Get-EventLog -LogName Security -InstanceId 4625'

'32. How do you enable account lockout policy?

Answer:

Group Policy → Account Policies → Account Lockout Policy.'

'33. How do you change user permissions on a folder?

Answer:

icacls "C:\folder" /grant User:F'

'34. How do you enable BitLocker on a Windows Server?

Answer:

Enable-BitLocker -MountPoint "C:" -EncryptionMethod AES256'

'35. What is NTFS vs. Share Permissions?

Answer:

NTFS Permissions – Apply to files & folders.
Share Permissions – Apply to network shares.'

'36. How do you create a new user account?

Answer:

New-ADUser -Name "JohnDoe" -SamAccountName "jdoe"'

'# Storage & Performance (41-50)

41. How do you check disk space?

Answer:

wmic logicaldisk get size,freespace,caption'

'42. How do you create a new partition?

Answer:

diskpart
create partition primary'

'43. How do you format a disk?

Answer:

format D: /FS:NTFS'

'44. How do you check Windows Server uptime?

Answer:

systeminfo | find "System Boot Time"'

'45. How do you monitor CPU and memory usage?

Answer:

taskmgr (GUI) or Get-Counter (PowerShell)'

'46. How do you optimize Windows Server performance?

Answer:

Disable unnecessary services, defragment drives, and monitor event logs.'

'47. How do you check Windows logs?

Answer:

eventvwr'

'48. How do you restart Windows Server remotely?

Answer:

shutdown /r /m \\ServerName'

'49. How do you enable RDP on Windows Server?

Answer:

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0'

'50. How do you schedule a task in Windows?

Answer:

Use Task Scheduler or schtasks command.'

)

last_index=$(( ${#questions_windows[@]} - 1 ))
Total_questions="50"
echo "Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${questions_windows[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo ' Total 50 questions'
done
clear
echo "End of questions. Thanks for participating"

        ;;

  b)
        

clear

scenario_windows_server=(
'1. A user is unable to log in, but other users can. How do you troubleshoot?

Answer:

Verify if the account is locked:
Get-ADUser -Identity <username> -Properties LockedOut
Unlock if necessary:
Unlock-ADAccount -Identity <username>
Check if the user is using the correct credentials.
Review event logs for Event ID 4625 (failed logins).'

'2. How do you recover a deleted AD user?

Answer:

Check Active Directory Recycle Bin if enabled.
Restore using PowerShell:

Get-ADObject -Filter "SamAccountName -eq "user1" -IncludeDeletedObjects | Restore-ADObject
If Recycle Bin is not enabled, restore from system backup.'

'3. You need to add a new domain controller (DC). How do you proceed?

Answer:

Install AD DS role on the new server.
Promote it to a domain controller using:
Install-ADDSDomainController -DomainName "example.com"
Verify replication using:
repadmin /replsummary
Check the event logs for errors.'

'4. Your AD replication is failing between DCs. How do you fix it?

Answer:

Check replication status:
repadmin /showrepl
Check event logs for Event ID 1311 (Replication failure).
Verify connectivity between DCs (e.g., firewall, DNS).
Run:
dcdiag /test:replications
If necessary, force replication:
repadmin /syncall.'

'5. Users are not getting group policies applied. How do you fix it?

Answer:

Run gpresult /r on the user’s PC to check applied policies.
Run rsop.msc to check policies visually.
Ensure policies are linked at the correct OU level.
Run:
gpupdate /force
Check for conflicting GPOs.'

'6. How do you reset a user’s password without changing it manually?

Answer:

Set-ADAccountPassword -Identity "user1" -Reset -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force).'

'7. Your AD database is corrupt. How do you recover it?

Answer:

Reboot into Directory Services Restore Mode (DSRM).
Run:

ntdsutil
activate instance ntds
files
integrity
If corruption is severe, restore from backup.'

'8. How do you deploy a software application using Group Policy?

Answer:

Place the .msi file in a shared folder.
Create a new GPO → Software Installation.
Assign it to users or computers.
Run gpupdate /force on clients.'

'9. You need to enforce a password policy via GPO. How?

Answer:

Edit Default Domain Policy → Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy.
Set password length, complexity, etc.'

'10. How do you apply a GPO to only a specific set of users?

Answer:

Use Security Filtering in the GPO settings.'

'11. Users cant access the file server. How do you diagnose?

Answer:

Ping the server:
ping <server-ip>
Check network settings:
ipconfig /all
Verify firewall settings:
netstat -ano.'

'12. A server has high network latency. How do you check?

Answer:

Use tracert to check hops:
tracert <server-ip>.'

'13. How do you extend a disk partition in Windows Server?

Answer:

Open Disk Management → Right-click the volume → Extend Volume.
Use PowerShell:
Resize-Partition -DriveLetter C -Size 100GB.'

'14. Your server’s disk is full. How do you troubleshoot?

Answer:

Use WinDirStat to check disk usage.
Run:
Get-Volume | Sort-Object -Property SizeRemaining
Clear temporary files:
cleanmgr.'

'15. A user reports unauthorized logins on their account. What do you do?

Answer:

Check Event Viewer → Security Logs → Look for Event ID 4625 (Failed logon attempts).
Disable the account temporarily if needed.'

'16. How do you set up Windows Server auditing for file access?

Answer:

Enable Audit Object Access in GPO.
Configure file auditing:
auditpol /set /category:"Object Access" /success:enable /failure:enable.'

'17. Your server is slow. How do you diagnose?

Answer:

Check CPU/memory usage:
taskmgr
Check disk activity:
resmon
Use Performance Monitor (perfmon.msc).'

'18. How do you recover from a failed Windows Server update?

Answer:

Boot into Safe Mode.
Run:
dism /online /cleanup-image /restorehealth
Uninstall the latest update:
wusa /uninstall /kb:<update-number>.'

'19. How do you set up a scheduled task to restart a server weekly?

Answer:

Use Task Scheduler: Create a new task to run:
shutdown /r /f /t 0.'

'20. How do you move FSMO roles to another DC?

Answer:

Run:

Move-ADDirectoryServerOperationMasterRole -Identity "NewDC" -OperationMasterRole PDCEmulator.'
)

last_index=$(( ${#scenario_windows_server[@]} - 1 ))
Total_questions="20"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_windows_server[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 20 questions'
done
clear
echo " End of questions. Thanks for participating"
        
        ;;

  c)
        
# Define MCQs with options and answers
QUESTIONS=(
    "What is the primary authentication protocol used in Windows Server Active Directory?|a) LDAP|b) Kerberos|c) NTLM|d) RADIUS|b"
    "Which Windows Server role is used for managing user identities and resources?|a) IIS|b) DNS Server|c) Active Directory Domain Services (AD DS)|d) DHCP Server|c"
    "Which command is used to check the current IP configuration in Windows Server?|a) ping|b) ipconfig|c) netstat|d) tracert|b"
    "What is the purpose of Group Policy in Windows Server?|a) To manage shared folders|b) To enforce security and configuration settings|c) To assign user permissions|d) To monitor network traffic|b"
    "Which feature allows multiple servers to share the load of network services?|a) Failover Clustering|b) Load Balancing|c) RAID|d) Hyper-V|b"
    "What is the primary function of DNS in Windows Server?|a) Assigning IP addresses|b) Translating domain names to IP addresses|c) Managing firewall rules|d) Enforcing group policies|b"
    "Which command is used to add a new user in Windows Server?|a) useradd|b) net user|c) adduser|d) newuser|b"
    "Which Windows Server edition is best suited for small businesses with basic needs?|a) Standard|b) Datacenter|c) Essentials|d) Enterprise|c"
    "Which Windows Server role is used to assign IP addresses dynamically to clients?|a) DNS Server|b) DHCP Server|c) Active Directory|d) IIS Server|b"
    "What is the default port number for Remote Desktop Protocol (RDP)?|a) 21|b) 443|c) 3389|d) 8080|c"
    "Which tool is used for monitoring system performance in Windows Server?|a) Task Manager|b) Performance Monitor|c) Event Viewer|d) Resource Monitor|b"
    "What does Hyper-V in Windows Server provide?|a) Virtualization|b) Storage management|c) Network security|d) User authentication|a"
    "Which command is used to restart a Windows Server remotely?|a) reboot|b) shutdown -r|c) restart|d) systemctl restart|b"
    "What is the primary function of Windows Server Update Services (WSUS)?|a) To manage firewall settings|b) To distribute Microsoft updates|c) To monitor server performance|d) To configure DNS records|b"
    "Which protocol is used for secure file transfers in Windows Server?|a) FTP|b) SFTP|c) TFTP|d) SMB|b"
    "Which command is used to view running services in Windows Server?|a) services.msc|b) net services|c) service list|d) tasklist|a"
    "What is the purpose of Windows Server Failover Clustering?|a) Load balancing|b) High availability and redundancy|c) User authentication|d) Software updates|b"
    "Which tool is used to manage Group Policies in Windows Server?|a) gpedit.msc|b) regedit|c) services.msc|d) secpol.msc|a"
    "Which file system is recommended for Windows Server installations?|a) FAT32|b) NTFS|c) exFAT|d) ext4|b"
    "What is the purpose of PowerShell in Windows Server?|a) File management|b) Scripting and automation|c) Database administration|d) Firewall configuration|b"
    "Which Windows Server feature provides centralized authentication and authorization services?|a) DHCP|b) Active Directory|c) IIS|d) BitLocker|b"
    "Which tool is used to manage disk partitions in Windows Server?|a) Disk Manager|b) fdisk|c) Diskpart|d) Partition Editor|c"
    "Which Windows Server feature allows remote desktop access to multiple users?|a) RDP|b) Terminal Services|c) VPN|d) Remote Assistance|b"
    "Which protocol does Windows Server use for network file sharing?|a) FTP|b) SMB|c) NFS|d) SCP|b"
    "What is the purpose of Windows Defender in Windows Server?|a) Virus protection|b) File sharing|c) User authentication|d) Backup and recovery|a"
    "Which command is used to add a computer to a domain?|a) net join|b) add-computer|c) domainadd|d) connect-domain|b"
    "Which Windows Server edition is optimized for cloud and virtualization?|a) Standard|b) Datacenter|c) Essentials|d) Foundation|b"
    "Which port does the Windows Server DHCP service use?|a) 53|b) 67|c) 80|d) 443|b"
    "Which Windows Server feature allows for backup and restore of data?|a) File History|b) Windows Server Backup|c) System Restore|d) BitLocker|b"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Windows Server MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Windows Server! 🚀"
 ;;

0) break ;;
*) echo "Invalid option, try agian." ;;

    esac
    done
    ;;

     iv)
     
     while true; do
     echo " You selected Micrsoft 365 skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " O365_way
     case $O365_way in
 a)
         
      clear

questions_O365=(

'# General Microsoft 365 Administration (1-10)

1. What is Microsoft 365, and how does it differ from Office 365?

Answer:

      Microsoft 365 is a cloud-based suite of apps and services, including Office 365,       Windows 10/11, and Enterprise Mobility + Security (EMS). Office 365 mainly includ      es productivity apps like Word, Excel, and Outlook.'

'2. What are the different Microsoft 365 subscription plans?

Answer:

      Business Plans: Business Basic, Business Standard, Business Premium.
      Enterprise Plans: E3, E5, F3.
      Education Plans: A1, A3, A5.
      Government Plans: GCC, GCC High, DoD.'

'3. How do you assign a license to a user in Microsoft 365?

Answer:

     Go to Microsoft 365 Admin Center → Users → Active Users.
     Select the user → Click "Licenses and Apps".
     Assign the required licenses.
     Click "Save changes".'

'4. How do you check service health in Microsoft 365?

Answer:

      Go to Microsoft 365 Admin Center → Health → Service Health.
      Use Microsoft 365 Service Health Dashboard.

      Use PowerShell:
      Get-MsolServiceStatus'

'5. What PowerShell module is used for Microsoft 365 administration?

Answer:

      Microsoft Graph PowerShell (modern, recommended).
      Azure AD Module (deprecated).
      Exchange Online Module for mailbox management.

      Install Microsoft Graph:

      Install-Module Microsoft.Graph -Scope CurrentUser
      Connect-MgGraph'

'# Exchange Online (11-20)

6. How do you create a shared mailbox in Exchange Online?

Answer:

      Go to Exchange Admin Center → Recipients → Shared Mailboxes.
      Click Add Shared Mailbox → Enter name and email.
      Assign members.

      PowerShell:

      New-Mailbox -Shared -Name "Support Mailbox" -PrimarySMTPAddress support@contoso.com'

'7. How do you convert a user mailbox into a shared mailbox?

Answer:

      Go to Exchange Admin Center → Recipients → Mailboxes.
      Select user → Click "Convert to Shared Mailbox".

      PowerShell:

      Set-Mailbox -Identity user@contoso.com -Type Shared'

'8. How do you enable litigation hold on a mailbox?

Answer:

      Open Exchange Admin Center → Recipients → Mailboxes.
      Select the mailbox → Compliance Management → Enable Litigation Hold.

      PowerShell:

      Set-Mailbox -Identity user@contoso.com -LitigationHoldEnabled $true'

'9. How do you block a users email access without deleting the account?

Answer:

      Go to Exchange Admin Center → Users → Select user → Sign-in status → Block sign-in.
      Remove all assigned licenses.

      PowerShell:

      Set-Mailbox -Identity user@contoso.com -AccountDisabled $true'

'10. How do you configure email forwarding for a user mailbox?

Answer:

     Open Exchange Admin Center → Mailboxes → Select user.
     Click Mail Flow Settings → Enable forwarding.

     PowerShell:

     Set-Mailbox -Identity user@contoso.com -ForwardingSMTPAddress user2@contoso.com -      DeliverToMailboxAndForward $true'
'11. How do you create a new Microsoft Teams policy?

Answer:

     Go to Teams Admin Center → Meetings → Meeting Policies.
     Click Add Policy, set permissions, and save.
     PowerShell:

     New-CsTeamsMeetingPolicy -Identity "NoVideoPolicy" -AllowIPVideo $false'
'12. How do you restrict external guest access in Teams?

Answer:

      Go to Teams Admin Center → Org-wide settings → Guest Access → Disable.
      Use PowerShell:

      Set-CsTeamsGuestMeetingConfiguration -AllowGuestMeetings $false'
'13. How do you prevent users from creating new Teams?

Answer:

Go to Microsoft 365 Admin Center → Groups → Settings.
Restrict Group creation to specific users.
PowerShell:

Set-MsolCompanySettings -AllowGroupCreation $false'
'14. How do you enable MFA (Multi-Factor Authentication) for all users?

Answer:

Go to Azure AD → Security → MFA.
Enforce MFA for all users.
PowerShell:

Get-MsolUser | Set-MsolUser -StrongAuthenticationRequirements'
'15. How do you prevent users from forwarding emails externally?

Answer:

Exchange Admin Center → Mail Flow → Rules → Block External Forwarding.
PowerShell:

New-TransportRule -Name "Block Auto Forwarding" -SentToScope NotInOrganization -RejectMessageEnhancedStatusCode 5.7.1'
'16. How do you enroll a Windows device in Microsoft Intune?

Answer:

Go to Settings → Accounts → Access work or school.
Click Enroll in MDM → Sign in with Microsoft 365 credentials.'
'17. How do you wipe a lost device using Intune?

Answer:

Go to Microsoft Endpoint Manager → Devices → Select device → "Wipe".
PowerShell:

Remove-IntuneManagedDevice -ManagedDeviceId <DeviceID>'
'18. How do you create a compliance policy in Intune?

Answer:

Go to Endpoint Manager → Compliance Policies.
Create a new policy with rules for password strength, encryption, etc.'
'19. How do you deploy a security baseline in Intune?

Answer:

Endpoint Manager → Security Baselines → Create Policy → Assign to devices.'
'20. How do you set up conditional access for Teams in Intune?

Answer:

Azure AD → Security → Conditional Access → New Policy.
Set conditions: "Require MFA for Teams".'
)
last_index=$(( ${#questions_O365[@]} - 1 ))
Total_questions="20"
echo " Total questions:$Total_questions"
echo " Lets practice linux scenario based interview questions and answers"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${questions_O365[$i]}"
        echo " "
        read -p ""
        clear
        echo ' Total 20 questions
 Press Enter key to clear the screen & move to the next question !'
done
clear
echo " Good ! You visited all questions and answers"
        

        ;;

  b)
       clear

scenario_O365=(

'1. Scenario: A new employee joins, and you need to quickly set up their Microsoft 365 account. How would you proceed?

✔ Answer:

Go to Microsoft 365 Admin Center → Users → Active Users → Add a user.
Assign a username, email, and initial password.
Assign appropriate licenses (E3, E5, Business, etc.).
Add to relevant Groups and configure security settings.
New-MsolUser -UserPrincipalName newuser@contoso.com -DisplayName "New User" -FirstName "John" -LastName "Doe" -LicenseAssignment "contoso:E3"'

'2. Scenario: A user reports they cannot sign in due to a blocked account. How do you resolve this?

✔ Answer:

Check sign-in status in Microsoft 365 Admin Center.
Unblock the account if its locked.
Reset password and ask the user to sign in again.
Verify sign-in logs in Azure AD for failed attempts.
Set-MsolUser -UserPrincipalName user@contoso.com -BlockCredential $false'

'3. Scenario: How do you ensure all users have MFA enabled?

✔ Answer:

Go to Azure AD → Security → MFA.
Configure a conditional access policy: Require MFA for all users.
Enforce Security Defaults for MFA.
Get-MsolUser | Set-MsolUser -StrongAuthenticationRequirements'

'4. Scenario: A user left the company, and their manager needs access to their emails. What do you do?

✔ Answer:

Convert the mailbox to a Shared Mailbox.
Assign the manager as a delegate.
Set-Mailbox -Identity user@contoso.com -Type Shared
Add-MailboxPermission -Identity user@contoso.com -User manager@contoso.com -AccessRights FullAccess'

'5. Scenario: How do you prevent users from auto-forwarding emails to external domains?

✔ Answer:

Exchange Admin Center → Mail Flow → Rules → Create a rule to block auto-forwarding.
New-TransportRule -Name "Block Auto Forwarding" -SentToScope NotInOrganization -RejectMessageEnhancedStatusCode 5.7.1'

'6. Scenario: A user deleted important emails permanently. How do you recover them?

✔ Answer:

If within 30 days, restore from the Deleted Items.
If beyond 30 days, use eDiscovery or Litigation Hold.
Search-Mailbox -Identity user@contoso.com -SearchQuery "subject: important email " -TargetMailbox admin@contoso.com -TargetFolder "RecoveredEmails"'

'7 Scenario: How do you restrict external users from joining Teams meetings?

✔ Answer:

Teams Admin Center → Org-wide settings → Guest Access → Disable.
Configure Azure AD Conditional Access for Teams.
Set-CsTeamsGuestMeetingConfiguration -AllowGuestMeetings $false'

'8. Scenario: How do you disable file sharing in Microsoft Teams for a specific group?

✔ Answer:

Teams Admin Center → Manage Teams → Select the team → Edit Sharing Settings.
Apply a Sensitivity Label to restrict sharing.'

'9.Scenario: How do you enforce email encryption for all outbound emails?

✔ Answer:

Compliance Admin Center → Sensitivity Labels → Create a label for encryption.
Apply DLP policies to enforce it.
Set-IRMConfiguration -InternalLicensingEnabled $true'

'10. Scenario: A user clicked on a phishing email and entered their credentials. What actions do you take?

✔ Answer:

Reset the users password immediately.
Block sign-in temporarily.
Check audit logs for unauthorized access.
Report phishing email in Microsoft Defender.
Set-MsolUser -UserPrincipalName user@contoso.com -BlockCredential $true'

'11. Scenario: A users laptop is lost. How do you wipe it remotely using Intune?

✔ Answer:

Microsoft Endpoint Manager → Devices → Select the device → Click "Wipe".
Remove-IntuneManagedDevice -ManagedDeviceId <DeviceID>'

'12. Scenario: How do you enforce BitLocker encryption on all company devices?

✔ Answer:

Endpoint Manager → Configuration Profiles → Create a profile for BitLocker enforcement.
Assign it to all devices.'

'13. Scenario: A user reports slow performance in Microsoft 365 apps on their laptop. How do you troubleshoot?

✔ Answer:

Check Microsoft 365 Health Status.
Run Office Repair.
Update the Office suite.
Check network latency and connectivity.'

'14. Scenario: How do you generate a report of all licensed users?

✔ Answer:


Get-MsolUser -All | Where-Object { $_.IsLicensed } | Select DisplayName, UserPrincipalName, Licenses'

'15. Scenario: How do you automate daily backup of Microsoft 365 audit logs?

✔ Answer:

Set up a PowerShell script to pull audit logs.
Schedule a task in Windows Task Scheduler.


Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) | Export-Csv "C:\AuditLogs.csv"'

'16. Scenario: How do you reset passwords for all users in bulk?

✔ Answer:

Get-MsolUser -All | Set-MsolUserPassword -ForceChangePasswordOnly $true -ForceChangePassword $true'
)



last_index=$(( ${#scenario_O365[@]} - 1 ))
Total_questions="16"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_O365[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 16 questions'
done
clear
echo " End of questions. Thanks for participating"
       
        ;;

  c)
   

# Define MCQs with options and answers
QUESTIONS=(
    "What is Microsoft 365?|a) A cloud-based productivity suite|b) A desktop operating system|c) A hardware product|d) A programming language|a"
    "Which service is used for email in Microsoft 365?|a) OneDrive|b) SharePoint|c) Exchange Online|d) Teams|c"
    "What is OneDrive primarily used for?|a) Email communication|b) Cloud storage|c) Video conferencing|d) Code development|b"
    "Which Microsoft 365 app is used for team collaboration and chat?|a) Word|b) Excel|c) Teams|d) Outlook|c"
    "What is SharePoint used for?|a) File storage and collaboration|b) Video streaming|c) Code editing|d) Virtual machine hosting|a"
    "Which Microsoft 365 plan includes the full Office desktop applications?|a) Microsoft 365 Business Basic|b) Microsoft 365 Apps for Business|c) Microsoft 365 Business Premium|d) Microsoft Defender|c"
    "Which app is used for video conferencing in Microsoft 365?|a) Teams|b) OneDrive|c) Excel|d) Outlook|a"
    "What does Microsoft 365 Defender provide?|a) Cloud storage|b) Cybersecurity protection|c) Email service|d) Spreadsheet software|b"
    "What is Microsoft Intune used for?|a) Device management and security|b) Email filtering|c) Cloud storage|d) Video conferencing|a"
    "Which application is used for creating and editing documents?|a) Excel|b) Word|c) PowerPoint|d) OneNote|b"
    "Which Microsoft 365 feature helps protect against phishing attacks?|a) Exchange Online Protection|b) Power Automate|c) Microsoft Whiteboard|d) OneNote|a"
    "What is the purpose of Power Automate in Microsoft 365?|a) Automating workflows and tasks|b) Creating spreadsheets|c) Video conferencing|d) Email management|a"
    "Which Microsoft 365 app is used for note-taking?|a) Word|b) OneNote|c) Excel|d) PowerPoint|b"
    "What is the primary use of Excel in Microsoft 365?|a) Writing documents|b) Managing emails|c) Creating spreadsheets and data analysis|d) Video calls|c"
    "Which Microsoft 365 service provides cloud-based email security?|a) Microsoft Defender|b) Exchange Online Protection|c) OneDrive|d) SharePoint|b"
    "Which Microsoft 365 tool is used to create professional presentations?|a) Word|b) Excel|c) PowerPoint|d) Teams|c"
    "What is the main function of Yammer in Microsoft 365?|a) Email communication|b) Enterprise social networking|c) Cloud storage|d) Project management|b"
    "Which Microsoft 365 service allows users to schedule and manage bookings?|a) Planner|b) Microsoft Bookings|c) OneDrive|d) SharePoint|b"
    "Which tool in Microsoft 365 helps manage tasks and projects?|a) Planner|b) Forms|c) Yammer|d) Outlook|a"
    "Which Microsoft 365 app is used to create surveys and quizzes?|a) OneDrive|b) Teams|c) Forms|d) SharePoint|c"
    "Which Microsoft 365 app provides a low-code platform for app development?|a) Power BI|b) Power Apps|c) OneDrive|d) Excel|b"
    "Which Microsoft 365 service helps businesses analyze data visually?|a) Power Automate|b) OneNote|c) Power BI|d) Yammer|c"
    "What is the primary function of Microsoft Stream?|a) Cloud storage|b) Enterprise video streaming|c) Email management|d) Task management|b"
    "Which Microsoft 365 feature enables email encryption?|a) Exchange Online Protection|b) Azure Information Protection|c) OneDrive|d) Yammer|b"
    "Which Microsoft 365 security feature enables Multi-Factor Authentication (MFA)?|a) OneDrive|b) Azure Active Directory|c) Yammer|d) Excel|b"
    "Which Microsoft 365 application is used for scheduling and managing meetings?|a) Teams|b) Planner|c) Yammer|d) Forms|a"
    "What is the maximum storage available per user in OneDrive for Business (with Microsoft 365 E3)?|a) 1TB|b) 5TB|c) 10TB|d) Unlimited|b"
    "Which Microsoft 365 service allows businesses to build AI-powered chatbots?|a) Power Apps|b) Power Virtual Agents|c) Power BI|d) Yammer|b"
    "Which Microsoft 365 tool allows employees to provide feedback and suggestions?|a) Yammer|b) Microsoft Forms|c) Planner|d) Power Automate|b"
    "Which Microsoft 365 application is best for real-time collaboration on documents?|a) Word Online|b) Excel Desktop|c) OneDrive|d) PowerPoint Desktop|a"
    "Which feature in Microsoft 365 helps prevent data loss by enforcing policies?|a) OneDrive|b) Data Loss Prevention (DLP)|c) Teams|d) Yammer|b"
    "Which Microsoft 365 feature enables secure access to corporate apps from unmanaged devices?|a) Azure AD Conditional Access|b) Microsoft Forms|c) SharePoint Online|d) Power BI|a"
    "Which Microsoft 365 app provides a kanban-style task management system?|a) Planner|b) Yammer|c) Excel|d) Teams|a"
    "Which Microsoft 365 service is used to manage business workflows?|a) Power Automate|b) Power BI|c) Yammer|d) OneDrive|a"
    "Which Microsoft 365 tool provides AI-driven insights for meeting effectiveness?|a) MyAnalytics|b) Yammer|c) OneNote|d) Planner|a"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Microsoft 365 MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Microsoft 365! 🚀"
;;

0) break ;;
*) echo "Invalid option. Try again." ;;
esac
done
;;

0) break ;;
*) echo "Invalid option. Try again. " ;;

esac

done

;;

 4)
        while true; do 
	echo " you have selected common windows & linux topic"
        echo " "
        echo " "
        echo " i)   Oracle SQL"
        echo " ii)  Veeam Backup application "
	echo " iii) Devops tools"
	echo " iv)  network_storage_security"
        echo "  0)  Back to the main menu"
	echo " "
        read -p "select skill:🎯 " common_skill
	clear
        echo " "
        case $common_skill in
 i)
     while true; do
     echo " You selected Oracle SQL skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " sql_way
     case $sql_way in
 a)
         ## Place code here for rhelvm_question

clear

sql_questions=(
"1. What is Oracle SQL?

Answer:

       Oracle SQL (Structured Query Language) is a database query language used to manage and manipulate Oracle databases."

"2. What is the difference between SQL and PL/SQL?

Answer:

       SQL is a structured query language used to interact with databases, while PL/SQL (Procedural Language/SQL) is an extension that allows procedural programming with SQL."

"3. What are the different types of SQL statements?

Answer:

       The main types of SQL statements are:
       - DDL (Data Definition Language): CREATE, ALTER, DROP
       - DML (Data Manipulation Language): INSERT, UPDATE, DELETE
       - DCL (Data Control Language): GRANT, REVOKE
       - TCL (Transaction Control Language): COMMIT, ROLLBACK"

"4. What is the difference between CHAR and VARCHAR2?

Answer:

       CHAR is a fixed-length data type, while VARCHAR2 is a variable-length data type that saves storage by using only the required space."

"5. What is a primary key in Oracle SQL?

Answer:

       A primary key is a unique identifier for a row in a table. It enforces uniqueness and does not allow NULL values."

"6. What is a foreign key?

Answer:

       A foreign key is a column or set of columns that establish a relationship between two tables by referencing the primary key of another table."

"7. What is the difference between WHERE and HAVING clause?

Answer:

       WHERE is used to filter records before grouping, while HAVING is used to filter records after applying GROUP BY."

"8. What is the difference between DELETE and TRUNCATE?

Answer:

       DELETE removes specific records and allows rollback, while TRUNCATE removes all records from a table and cannot be rolled back."

"9. What is an index in Oracle SQL?

Answer:

       An index improves query performance by creating a fast lookup structure for table data."

"10. What are the different types of indexes in Oracle?

Answer:

       The types of indexes in Oracle include:
       - B-tree Index
       - Bitmap Index
       - Unique Index
       - Composite Index"

"11. What is a sequence in Oracle SQL?

Answer:

       A sequence is a database object used to generate unique numeric values, often used for primary keys."

"12. What is a view in Oracle SQL?

Answer:

       A view is a virtual table based on a SELECT query that does not store data but presents results dynamically."

"13. What is a synonym in Oracle SQL?

Answer:

       A synonym is an alias for a database object, making it easier to reference objects across schemas."

"14. What is the difference between UNION and UNION ALL?

Answer:

       UNION removes duplicate records, whereas UNION ALL includes all records, including duplicates."

"15. What is a materialized view?

Answer:

       A materialized view stores query results physically for improved performance and supports refresh mechanisms."

"16. What are constraints in Oracle SQL?

Answer:

       Constraints enforce rules on data integrity. Common types include:
       - PRIMARY KEY
       - FOREIGN KEY
       - UNIQUE
       - CHECK
       - NOT NULL"

"17. What is the difference between LEFT JOIN and RIGHT JOIN?

Answer:

       LEFT JOIN returns all records from the left table and matching records from the right table, while RIGHT JOIN returns all records from the right table and matching records from the left table."

"18. What is the difference between an inline view and a normal view?

Answer:

       An inline view is a subquery used in the FROM clause, whereas a normal view is a stored database object."

"19. What is an Oracle cursor?

Answer:

       A cursor is a pointer that retrieves and processes records row-by-row in PL/SQL."

"20. What is the purpose of the ROWNUM keyword in Oracle SQL?

Answer:

       ROWNUM assigns a unique number to each row in a query result, often used for limiting results."

"21. What is the difference between ROWNUM and ROW_NUMBER()?

Answer:

       ROWNUM is assigned before sorting, whereas ROW_NUMBER() assigns numbers after sorting, allowing ranking."

"22. What is the difference between NVL and COALESCE?

Answer:

       NVL returns the first non-null value between two arguments, while COALESCE returns the first non-null value from a list of arguments."

"23. What is a trigger in Oracle SQL?

Answer:

       A trigger is a stored procedure that automatically executes in response to an event such as INSERT, UPDATE, or DELETE."

"24. What are the types of triggers in Oracle?

Answer:

       Types of triggers include:
       - BEFORE and AFTER triggers
       - ROW-level and STATEMENT-level triggers
       - INSTEAD OF triggers"

"25. What is a PL/SQL package?

Answer:

       A PL/SQL package is a collection of procedures, functions, and variables grouped as a single unit."

"26. What is an exception in PL/SQL?

Answer:

       An exception is an error-handling mechanism that allows custom handling of runtime errors."

"27. What is an implicit cursor in Oracle SQL?

Answer:

       An implicit cursor is automatically created by Oracle for DML operations like SELECT INTO, INSERT, UPDATE, and DELETE."

"28. What is an explicit cursor?

Answer:

       An explicit cursor is a user-defined cursor that allows row-by-row processing of query results."

"29. What is the difference between COMMIT and ROLLBACK?

Answer:

       COMMIT saves all changes permanently, while ROLLBACK undoes all uncommitted changes."

"30. How do you find duplicate records in an Oracle table?

Answer:

       You can find duplicate records using GROUP BY and HAVING clauses:
       SELECT column_name, COUNT(*)
       FROM table_name
       GROUP BY column_name
       HAVING COUNT(*) > 1;"


)

last_index=$(( ${#sql_questions[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${sql_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo ' Total 50 questions'
done
clear
echo "End of questions. Thanks for participating"

 ;;
    

 b)
clear
v="$session"
scenario_sql=(
"Basic SQL Scenarios (1-10)
1 Scenario: How do you retrieve all records from a table named 'employees'?

✔ Answer: Use the query:

SELECT * FROM employees;"
"2 Scenario: How do you find employees with a salary greater than 50,000

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary > 50000;"
"3 Scenario: How do you get the total number of employees in a department

✔ Answer: Use the query:

SELECT department_id, COUNT(*) FROM employees GROUP BY department_id;"
"4 Scenario: How do you retrieve the highest salary in the company

✔ Answer: Use the query:

SELECT MAX(salary) FROM employees;"
"5 Scenario: How do you fetch employees whose names start with 'A'

✔ Answer: Use the query:

SELECT * FROM employees WHERE name LIKE 'A%';"
"6 Scenario: How do you find duplicate records in a table

✔ Answer: Use the query:

SELECT column_name, COUNT(*)
FROM table_name
GROUP BY column_name
HAVING COUNT(*) > 1;"
"7 Scenario: How do you delete duplicate rows from a table while keeping one copy

✔ Answer: Use the query:

DELETE FROM employees
WHERE rowid NOT IN (SELECT MIN(rowid) FROM employees GROUP BY name, salary);"
"8 Scenario: How do you update salaries by 10% for all employees

✔ Answer: Use the query:

UPDATE employees SET salary = salary * 1.10;"
"9 Scenario: How do you get the first three highest salaries

✔ Answer: Use the query:

SELECT DISTINCT salary
FROM employees
ORDER BY salary DESC
FETCH FIRST 3 ROWS ONLY;"
"10 Scenario: How do you retrieve employees who joined in the last 30 days

✔ Answer: Use the query:

SELECT * FROM employees WHERE hire_date >= SYSDATE - 30;
Intermediate SQL Scenarios (11-20)"
"11 Scenario: How do you check if a table exists in Oracle SQL

✔ Answer: Use the query:

SELECT table_name FROM user_tables WHERE table_name = 'EMPLOYEES';"
"12 Scenario: How do you rename a column in an existing table

✔ Answer: Use the query:

ALTER TABLE employees RENAME COLUMN old_name TO new_name;"
"13 Scenario: How do you find employees with NULL values in their email column

✔ Answer: Use the query:

SELECT * FROM employees WHERE email IS NULL;"
"14 Scenario: How do you add a new column 'bonus' to the employees table

✔ Answer: Use the query:

ALTER TABLE employees ADD bonus NUMBER(10,2);"
"15 Scenario: How do you get the current date and time in Oracle SQL

✔ Answer: Use the query:

SELECT SYSDATE FROM dual;"
"16 Scenario: How do you concatenate first and last names in the employees table

✔ Answer: Use the query:

SELECT first_name || ' ' || last_name AS full_name FROM employees;"
"17 Scenario: How do you create an index on the 'email' column of the employees table

✔ Answer: Use the query:

CREATE INDEX email_idx ON employees(email);"
"18 Scenario: How do you check the structure of a table

✔ Answer: Use the query:

DESC employees;"
"19 Scenario: How do you fetch employees who joined between two dates

✔ Answer: Use the query:

SELECT * FROM employees WHERE hire_date BETWEEN '01-JAN-2023' AND '31-DEC-2023';"
"20 Scenario: How do you list all constraints on a table

✔ Answer: Use the query:

SELECT constraint_name, constraint_type
FROM user_constraints
WHERE table_name = 'EMPLOYEES';
Advanced SQL Scenarios (21-30)"
"21 Scenario: How do you fetch the second highest salary in the employees table

✔ Answer: Use the query:

SELECT DISTINCT salary FROM employees ORDER BY salary DESC OFFSET 1 ROW FETCH NEXT 1 ROW ONLY;"
"22 Scenario: How do you count the number of rows in a table

✔ Answer: Use the query:

SELECT COUNT(*) FROM employees;"
"23 Scenario: How do you drop a table permanently

✔ Answer: Use the query:

DROP TABLE employees;"
"24 Scenario: How do you create a view to display employees earning above 60,000

✔ Answer: Use the query:

CREATE VIEW high_salary_employees AS
SELECT * FROM employees WHERE salary > 60000;"
"25 Scenario: How do you check all indexes on a table

✔ Answer: Use the query:

SELECT index_name FROM user_indexes WHERE table_name = 'EMPLOYEES';"
"26 Scenario: How do you list all stored procedures in a database

✔ Answer: Use the query:

SELECT object_name FROM user_procedures;"
"27 Scenario: How do you find the length of a string in SQL

✔ Answer: Use the query:

SELECT LENGTH('Oracle SQL') FROM dual;"
"28 Scenario: How do you round a decimal value to 2 places

✔ Answer: Use the query:

SELECT ROUND(123.4567, 2) FROM dual;"
"29 Scenario: How do you fetch employees with salaries between 40,000 and 70,000

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary BETWEEN 40000 AND 70000;"
"30 Scenario: How do you change the datatype of a column

✔ Answer: Use the query:

ALTER TABLE employees MODIFY salary NUMBER(12,2);
Expert-Level SQL Scenarios (31-50)"
"31 Scenario: How do you find employees whose salary is the same as another employee

✔ Answer: Use the query:

SELECT e1.* FROM employees e1 JOIN employees e2 ON e1.salary = e2.salary AND e1.employee_id <> e2.employee_id;"
"32 Scenario: How do you create a foreign key in Oracle SQL

✔ Answer: Use the query:

ALTER TABLE orders ADD CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id);"
"33 Scenario: How do you get the first 5 records of a table

✔ Answer: Use the query:

SELECT * FROM employees FETCH FIRST 5 ROWS ONLY;


Expert-Level SQL Scenarios (34-50)"
"34 Scenario: How do you create a stored procedure to increase employee salaries by 10%

✔ Answer: Use the query:

CREATE PROCEDURE increase_salary AS
BEGIN
    UPDATE employees SET salary = salary * 1.10;
    COMMIT;
END;"
"35 Scenario: How do you fetch the nth highest salary from a table

✔ Answer: Use the query:

SELECT DISTINCT salary FROM employees ORDER BY salary DESC OFFSET (n-1) ROWS FETCH NEXT 1 ROW ONLY;"
"36 Scenario: How do you list all columns of a table

✔ Answer: Use the query:

SELECT column_name FROM user_tab_columns WHERE table_name = 'EMPLOYEES';"
"37 Scenario: How do you remove a column from a table

✔ Answer: Use the query:

ALTER TABLE employees DROP COLUMN bonus;"
"38 Scenario: How do you check if a value exists in a table

✔ Answer: Use the query:

SELECT 1 FROM employees WHERE employee_id = 100;"
"39 Scenario: How do you find the employees with the lowest salary

✔ Answer: Use the query:

SELECT * FROM employees WHERE salary = (SELECT MIN(salary) FROM employees);"
"40 Scenario: How do you update multiple rows with different values

✔ Answer: Use the query:

UPDATE employees SET salary =
  CASE WHEN department_id = 10 THEN salary * 1.10
       WHEN department_id = 20 THEN salary * 1.05
       ELSE salary
  END;"
"41 Scenario: How do you fetch employees whose hire date is in February

✔ Answer: Use the query:

SELECT * FROM employees WHERE TO_CHAR(hire_date, 'MM') = '02';"
"42 Scenario: How do you delete all records from a table without deleting the structure

✔ Answer: Use the query:

TRUNCATE TABLE employees;"
"43 Scenario: How do you find all tables in the database owned by the current user

✔ Answer: Use the query:

SELECT table_name FROM user_tables;"
"44 Scenario: How do you list all sequences in the database

✔ Answer: Use the query:

SELECT sequence_name FROM user_sequences;"
"45 Scenario: How do you create a sequence to generate unique employee IDs

✔ Answer: Use the query:

CREATE SEQUENCE emp_id_seq START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;"
"46 Scenario: How do you use a sequence in an INSERT statement

✔ Answer: Use the query:

INSERT INTO employees (employee_id, name, salary)
VALUES (emp_id_seq.NEXTVAL, 'John Doe', 60000);"
"47 Scenario: How do you remove all employees who have been terminated

✔ Answer: Use the query:

DELETE FROM employees WHERE status = 'Terminated';"
"48 Scenario: How do you check database session information

✔ Answer: Use the query:

SELECT * FROM echo v$ session;"
"49 Scenario: How do you join two tables to fetch employee names and department names

✔ Answer: Use the query:

SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department_id = d.department_id;"
"50 Scenario: How do you fetch the last inserted record in a table

✔ Answer: Use the query:

SELECT * FROM employees WHERE rowid = (SELECT MAX(rowid) FROM employees);"

)

last_index=$(( ${#scenario_sql[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_sql[$i]}"
        echo " "
         echo " "
          echo " "
           echo " "
            echo " "
             echo " "
              echo " "
               echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 50 questions'
done
clear
echo " End of questions. Thanks for participating"


        ;;

  c)


# Define MCQs with options and answers
QUESTIONS=(
    "What is SQL?|a) A programming language|b) A query language|c) A markup language|d) A scripting language|b"
    "Which SQL command is used to retrieve data from a database?|a) GET|b) SELECT|c) FETCH|d) RETRIEVE|b"
    "What does the acronym DDL stand for?|a) Data Definition Language|b) Data Deployment Language|c) Dynamic Data Language|d) Data Derivation Language|a"
    "Which of the following is a DML command?|a) CREATE|b) ALTER|c) INSERT|d) DROP|c"
    "Which SQL clause is used to filter results?|a) WHERE|b) ORDER BY|c) GROUP BY|d) FILTER|a"
    "What does the JOIN clause do in SQL?|a) Merges two databases|b) Combines rows from two or more tables|c) Sorts query results|d) Removes duplicate records|b"
    "Which SQL statement is used to remove all records from a table without deleting the table itself?|a) DELETE|b) DROP|c) TRUNCATE|d) REMOVE|c"
    "What is the purpose of the GROUP BY clause?|a) Sorts query results|b) Aggregates data by column values|c) Filters data|d) Removes duplicate records|b"
    "Which SQL function is used to count the number of rows?|a) SUM()|b) COUNT()|c) AVG()|d) MAX()|b"
    "Which constraint is used to ensure all values in a column are unique?|a) NOT NULL|b) UNIQUE|c) CHECK|d) PRIMARY KEY|b"
    "What is a primary key?|a) A unique identifier for each row in a table|b) A foreign key reference|c) A column that stores indexes|d) A table constraint|a"
    "Which SQL command is used to modify existing records in a table?|a) CHANGE|b) UPDATE|c) MODIFY|d) ALTER|b"
    "What does the HAVING clause do?|a) Filters aggregate results|b) Orders query results|c) Joins tables|d) Groups query results|a"
    "Which SQL keyword is used to retrieve unique values?|a) DISTINCT|b) UNIQUE|c) DIFFERENT|d) SEPARATE|a"
    "Which of the following is a valid SQL data type?|a) INT|b) DECIMAL|c) VARCHAR|d) All of the above|d"
    "What is the default sorting order of ORDER BY?|a) ASC|b) DESC|c) RANDOM|d) NONE|a"
    "Which statement is used to create a new table in SQL?|a) MAKE TABLE|b) NEW TABLE|c) CREATE TABLE|d) ADD TABLE|c"
    "Which SQL keyword is used to delete a table permanently?|a) REMOVE|b) DELETE|c) DROP|d) ERASE|c"
    "What is a foreign key?|a) A key from another table linking relationships|b) A unique column identifier|c) A primary key|d) A stored procedure|a"
    "Which operator is used for pattern matching in SQL?|a) LIKE|b) MATCH|c) SEARCH|d) FIND|a"
    "Which function returns the current date in SQL?|a) GETDATE()|b) CURDATE()|c) NOW()|d) All of the above|d"
    "What is an index in SQL?|a) A lookup table to speed up queries|b) A method to insert records|c) A table constraint|d) A stored procedure|a"
    "Which SQL clause is used to rename a column?|a) CHANGE|b) MODIFY|c) AS|d) ALTER COLUMN|c"
    "What is normalization in SQL?|a) Reducing data redundancy|b) Increasing data redundancy|c) Deleting data|d) Backing up data|a"
    "Which SQL function calculates the average value of a column?|a) SUM()|b) AVG()|c) COUNT()|d) MIN()|b"
    "What is a stored procedure?|a) A predefined SQL script|b) A temporary table|c) A function that updates records|d) A backup process|a"
    "Which SQL command is used to create an index?|a) MAKE INDEX|b) NEW INDEX|c) CREATE INDEX|d) ADD INDEX|c"
    "What is a view in SQL?|a) A virtual table|b) A stored procedure|c) A database function|d) A constraint|a"
    "Which SQL clause is used to check for a null value?|a) = NULL|b) IS NULL|c) CHECK NULL|d) FIND NULL|b"
    "Which command is used to roll back a transaction?|a) ROLLBACK|b) UNDO|c) CANCEL|d) REVERSE|a"
    "Which SQL statement is used to add new columns to a table?|a) MODIFY TABLE|b) ADD COLUMN|c) ALTER TABLE|d) CHANGE TABLE|c"
    "Which SQL function finds the highest value in a column?|a) MIN()|b) AVG()|c) MAX()|d) COUNT()|c"
    "What is a composite key?|a) A key composed of multiple columns|b) A primary key|c) A foreign key|d) A unique constraint|a"
    "Which SQL statement removes duplicate rows?|a) DELETE DISTINCT|b) UNIQUE|c) DISTINCT|d) FILTER|c"
    "What does the UNION operator do?|a) Combines results from multiple SELECT statements|b) Joins two tables|c) Merges data types|d) Deletes duplicates|a"
    "What is the difference between UNION and UNION ALL?|a) UNION removes duplicates, UNION ALL does not|b) UNION ALL removes duplicates, UNION does not|c) UNION is faster|d) There is no difference|a"
    "Which SQL clause is used to check a condition in a query?|a) IF|b) CASE|c) CHECK|d) VERIFY|b"
    "Which SQL function finds the lowest value in a column?|a) MIN()|b) AVG()|c) MAX()|d) COUNT()|a"
    "Which keyword is used to remove an existing view?|a) DELETE VIEW|b) DROP VIEW|c) REMOVE VIEW|d) ERASE VIEW|b"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Oracle SQL MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Oracle SQL! 🚀"

         ## place code here rhelvm_quiz
;;

0) break ;;
*) echo "Invalid option try again." ;;

esac

done
;;

 ii)
     while true; do
     echo " You selected Veeam skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " veeam_way
     case $veeam_way in
 a)
         ## Place code here for rhelvm_question

clear

questions_veeam=(
'1. What is Veeam Backup & Replication?

Answer:

Veeam Backup & Replication is a data protection solution that provides backup, recoveryand replication for virtual, physical, and cloud environments.'

'2. What are the key components of Veeam Backup & Replication?

Answer:

Veeam Backup Server, Proxy Server, Repository, Backup Agents, and Enterprise Manager.'

'3. What is the difference between forward and reverse incremental backup in Veeam?

Answer:

Forward incremental creates a full backup first, followed by incremental backups. Reverse incremental creates a full backup and then applies changes to it, generating synthetic full backups.'

'4. What is the difference between Veeam Backup & Replication and Veeam ONE?

Answer:

Veeam Backup & Replication focuses on data protection, while Veeam ONE provides monitoring,reporting, and analytics for Veeam environments.'

'5. How does Veeam Backup & Replication perform application-aware processing?

Answer:

It uses VSS (Volume Shadow Copy Service) to ensure application-consistent backups for databases like SQL Server and Exchange.'

'6. What is Veeam Cloud Connect?

Answer:

A feature that allows offsite backup and replication to Veeam Cloud Service Providers (VCSPs) without setting up complex VPNs.'

'7. What is SureBackup in Veeam?

Answer:

SureBackup verifies the recoverability of backups by running them in an isolated environment and performing health checks.'

'8. What is Veeam’s Instant VM Recovery?

Answer:

Instant VM Recovery allows users to restore a VM directly from the backup repository without waiting for full restoration.'

'9. How does Veeam handle ransomware protection?

Answer:

Veeam offers immutable backups, air-gapped storage, and integration with object storage to protect against ransomware attacks.'

'10. What are the different backup job types in Veeam?

Answer:

Full Backup, Incremental Backup, Reverse Incremental Backup, and Synthetic Full Backup.'

'11. What is Veeam Backup Copy Job?

Answer:

A feature that copies existing backups to another repository for redundancy and long-term storage.'

'12. How do you configure Veeam to send backup job email notifications?

Answer:

Configure SMTP settings under Veeam Backup Server → General Options → Email Notifications.'

'13. What is the 3-2-1 backup rule in Veeam?

Answer:

Keep 3 copies of data on 2 different media types, with 1 copy stored offsite.'

'14. What is Veeam Explorers?

Answer:

Veeam Explorers are tools used to restore application-specific items like Exchange, SQL Server, SharePoint, and Active Directory.'

'15. How does Veeam handle deduplication?

Answer:

Veeam uses built-in deduplication at the backup repository level and can integrate with hardware deduplication appliances.'

'16. What is a Veeam Backup Proxy?

Answer:

A component that handles data traffic between backup sources and repositories to optimize backup performance.'

'17. How does Veeam Backup for Microsoft 365 work?

Answer:

It allows users to back up and restore Exchange Online, SharePoint Online, OneDrive, and Teams data.'

'18. What is Veeam Replication, and how does it work?

Answer:

Replication creates VM copies in a DR site, allowing fast failover in case of primary site failure.'

'19. What are Veeam Backup Repositories?

Answer:

Storage locations where backup files are stored, including local disk, NAS, object storage, and cloud.'

'20. How does Veeam integrate with VMware vSphere?

Answer:

It uses vSphere APIs to perform agentless backups and replication of virtual machines.'

'21. What is Veeam WAN Accelerator?

Answer:

A feature that optimizes backup data transfer over WAN links using compression and deduplication.'

'22. How does Veeam handle encryption for backups?

Answer:

It provides AES-256 encryption for backup files both in transit and at rest.'

'23. What is Veeam Instant File-Level Recovery (IFLR)?

Answer:

A feature that allows users to recover individual files from backups without restoring the full VM.'

'24. How does Veeam manage long-term retention of backups?

Answer:

By integrating with tape storage, object storage, and archive tiers for extended retention policies.'

'25. How does Veeam support backup to object storage?

Answer:

By using Veeam Scale-out Backup Repository with object storage tiers like Amazon S3, Azure Blob, and Wasabi.'

'26. What is Veeam SureReplica?

Answer:

A feature that verifies replicated VMs by running them in an isolated environment.'

'27. How do you perform a VM failover in Veeam?

Answer:

Use Veeam Backup & Replication to manually or automatically switch to a replica VM in case of failure.'

'28. What is the difference between Full and Synthetic Full Backup?

Answer:

A Full Backup reads data from the source, while a Synthetic Full Backup creates a full backup from existing incremental files without re-reading data.'

'29. How do you schedule backup jobs in Veeam?

Answer:

Go to Backup Job Settings → Configure Schedule → Set Frequency (Daily, Weekly, etc.).'

'30. What is Veeam DataLabs?

Answer:

A feature that allows users to create isolated environments for testing and security analysis using backups.'

'31. How does Veeam handle backup chain management?

Answer:

It allows users to set retention policies for deleting old backup files while keeping recent backups available.'

'32. What is Veeam Staged Restore?

Answer:

A feature that lets users remove sensitive data from a backup before restoring it.'

'33. How do you configure Veeam to use immutable backups?

Answer:

Enable immutability in object storage settings for Amazon S3 or other compatible storage providers.'

'34. What is Veeam’s Guest Processing feature?

Answer:

A feature that ensures application-consistent backups using VSS integration.'

'35. How do you restore an entire VM using Veeam?

Answer:

Use Restore Wizard in Veeam Backup & Replication → Select "Entire VM Restore".'

'36. How do you monitor Veeam Backup jobs?

Answer:

Use Veeam ONE for real-time monitoring and reporting on backup jobs.'

'37. What is Veeam’s Instant Disk Recovery?

Answer:

Allows users to restore individual VM disks instantly without full VM restoration.'

'38. How does Veeam support Kubernetes backups?

Answer:

By using Kasten K10, a Kubernetes-native backup and disaster recovery solution.'

'39. What are the storage options for Veeam backups?

Answer:

Local storage, NAS, Tape, Object Storage, and Cloud providers.'

'40. How do you perform a granular recovery of an Active Directory object?

Answer:

Use Veeam Explorer for Active Directory to restore specific objects.'

'41. What is a Veeam Agent?

Answer:

A lightweight software that allows backup of physical servers, workstations, and cloud instances.'

'42. How does Veeam handle SQL Server backups?

Answer:

It uses VSS integration and Veeam Explorer for SQL to restore databases.'

'43. What is Veeam Backup Validator?

Answer:

A tool that checks backup file integrity and consistency.'

'44. How do you configure offsite backup replication in Veeam?

Answer:

Use Veeam Cloud Connect or set up a secondary backup repository.'

'45. How do you configure Veeam for Microsoft Azure backup?

Answer:

Use Veeam Backup for Azure, which provides native snapshot-based protection.'

'46. What is Veeam Object Lock?

Answer:

A feature that prevents deletion or modification of backup files for a specified period.'

'47. How do you test a Veeam backup restore?

Answer:

Use SureBackup to validate the recoverability of backups.'

'48. What is Veeam Backup Immutability?

Answer:

A security feature that prevents backup file deletion or alteration.'

'49. How does Veeam handle backup compression?

Answer:

Uses inline deduplication and compression to reduce backup storage usage.'

'50. How do you automate Veeam backups?

Answer:

Use PowerShell scripts or Veeam Backup Enterprise Manager for automation.'

        )


last_index=$(( ${#questions_veeam[@]} - 1 ))
Total_questions="50"
echo " Total questions:$Total_questions"
echo " "
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${questions_veeam[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo "total questions:50"
done
clear
echo " Good ! You visited all questions and answers"


        ;;

  b)
          ## place code here rhelvm_scenario
     clear

scenario_veeam=(
'1 Scenario: A Veeam backup job is failing. How do you troubleshoot?

✔ Answer:

 Check job logs in Veeam Backup & Replication, ensure the backup repository has enough space, verify that the VM is accessible, and confirm that Veeam services are running.'

'2 Scenario: You need to restore a single file from a backup. How do you do it?

✔ Answer:

 Use Veeam File-Level Restore to mount the backup and extract the required file.'

'3 Scenario: A backup repository is full. How do you resolve this?

✔ Answer:

 Enable retention policies, use backup compression, move old backups to archive storage, or expand the repository.'

'4 Scenario: How do you ensure Veeam backups are protected against ransomware?

✔ Answer:

 Use immutable backups, enable encryption, implement air-gapped storage, and use Veeam SureBackup to verify backup integrity.'

'5 Scenario: A Veeam replication job is running slowly. How do you optimize it?

✔ Answer:

 Enable WAN acceleration, adjust job scheduling, use changed block tracking (CBT), and optimize network bandwidth.'

'6 Scenario: How do you migrate a VM from one host to another using Veeam?

✔ Answer:

 Use Veeam Quick Migration to move VMs between hosts with minimal downtime.'

'7 Scenario: A backup job is stuck at 99%. How do you fix this?

✔ Answer:

 Check for VSS snapshot issues, verify storage availability, restart the Veeam services, and review job logs.'

'8 Scenario: How do you configure backup encryption in Veeam?

✔ Answer:

 Enable encryption under backup job settings, set a strong password, and store encryption keys securely.'

'9 Scenario: A VM fails to back up due to snapshot issues. How do you troubleshoot?

✔ Answer:

 Manually remove orphaned snapshots, ensure enough datastore space, and restart the VSS services on the VM.'

'10 Scenario: How do you monitor Veeam backup job performance?

✔ Answer:

 Use Veeam ONE to track job success rates, backup speeds, and storage utilization.'

'11 Scenario: How do you test a backup’s integrity in Veeam?

✔ Answer:

 Use Veeam SureBackup to automatically verify backups by running them in an isolated environment.'

'12 Scenario: You need to back up a physical server. How do you configure it in Veeam?

✔ Answer:

 Install Veeam Agent for Windows/Linux and create a backup job targeting a repository or cloud storage.'

'13 Scenario: How do you reduce backup storage consumption in Veeam?

✔ Answer:

 Enable deduplication, use incremental backups, and set proper retention policies.'

'14 Scenario: How do you recover an entire VM using Veeam?

✔ Answer:

 Use Instant VM Recovery or full VM restore from a backup.'

'15 Scenario: How do you schedule backups in Veeam?

✔ Answer:

 Configure backup job scheduling under job settings in Veeam Backup & Replication.'

'16 Scenario: A backup job fails with a “Repository Unavailable” error. How do you fix it?

✔ Answer:

 Check repository disk space, verify network connectivity, and restart Veeam Backup services.'

'17 Scenario: How do you back up Microsoft 365 (Exchange, SharePoint, OneDrive) with Veeam?

✔ Answer:

 Use Veeam Backup for Microsoft 365 to configure backups for Exchange, SharePoint, and OneDrive.'

'18 Scenario: A Veeam backup copy job is slow. How do you improve its speed?

✔ Answer:

 Enable WAN acceleration, use parallel processing, and optimize network connectivity.'

'19 Scenario: How do you configure Veeam for cloud backups?

✔ Answer:

 Add an object storage repository (AWS S3, Azure Blob, etc.) and configure a Scale-Out Backup Repository.'

'20 Scenario: How do you restore Active Directory objects using Veeam?

✔ Answer:

 Use Veeam Explorer for Active Directory to restore users, groups, or entire objects.'

'21 Scenario: How do you back up SQL databases with Veeam?

✔ Answer:

 Use Veeam Explorer for Microsoft SQL Server with transaction log backups for point-in-time recovery.'

'22 Scenario: A backup chain is corrupted. How do you resolve this?

✔ Answer:

 Perform an Active Full Backup to create a new backup chain and delete the corrupted files.'

'23 Scenario: How do you automate backup reports in Veeam?

✔ Answer:

 Use Veeam ONE to generate scheduled reports on backup job status and performance.'

'24 Scenario: A Linux VM is failing to back up. How do you troubleshoot?

✔ Answer:

 Ensure Veeam has correct SSH credentials, check VSS settings, and verify disk space on the VM.'

'25 Scenario: How do you back up VMware vSphere using Veeam?

✔ Answer:

 Add the vCenter Server or ESXi host in Veeam, then configure VM backup jobs.'

'26 Scenario: How do you perform an offsite backup with Veeam?

✔ Answer:

 Use Veeam Cloud Connect to send backups to a remote cloud provider.'

'27 Scenario: How do you restore a deleted Exchange mailbox item in Veeam?

✔ Answer:

 Use Veeam Explorer for Microsoft Exchange to browse and restore mailbox items.'

'28 Scenario: How do you configure backup retention policies in Veeam?

✔ Answer:

 Set the desired number of restore points in the backup job settings.'

'29 Scenario: A Veeam backup job is reporting high latency. How do you fix it?

✔ Answer:

 Optimize storage performance, adjust backup window scheduling, and verify network speed.'

'30 Scenario: How do you back up Kubernetes workloads with Veeam?

✔ Answer:

 Use Veeam Kasten K10 to protect Kubernetes applications and persistent volumes.'

'31 Scenario: How do you protect Veeam backups from accidental deletion?

✔ Answer:

 Enable immutable storage and configure backup copy jobs for redundancy.'

'32 Scenario: How do you back up Nutanix AHV VMs with Veeam?

✔ Answer:

 Add the Nutanix AHV cluster in Veeam and configure VM backup jobs.'

'33 Scenario: How do you restore a SharePoint document library using Veeam?

✔ Answer:

 Use Veeam Explorer for SharePoint to restore specific files or libraries.'

'34 Scenario: A backup job is failing due to a locked file. How do you resolve this?

✔ Answer:

 Use Application-Aware Processing to properly capture open files.'

'35 Scenario: How do you configure Veeam for long-term archival storage?

✔ Answer:

 Use tape backups or integrate with cloud archival storage like AWS Glacier or Azure Archive Storage.'

'36 Scenario: How do you back up NAS file shares using Veeam?

✔ Answer:

 Use Veeam NAS Backup to protect SMB/NFS file shares.'

'37 Scenario: How do you troubleshoot Veeam transport mode issues?

✔ Answer:

 Check if Direct SAN Access, HotAdd, or Network Mode is correctly configured based on storage type.'

'38 Scenario: A backup job is running significantly slower than usual. What do you check?

✔ Answer:

 Review job logs, check storage latency, optimize deduplication settings, and verify network performance.'

'39 Scenario: How do you configure Veeam to send backup alerts via email?

✔ Answer:

 Configure SMTP settings in Veeam Backup & Replication under Email Notifications.'

'40 Scenario: How do you use Veeam to ensure regulatory compliance?

✔ Answer:

 Implement encryption, immutability, role-based access control (RBAC), and compliance reporting.'

)

last_index=$(( ${#scenario_veeam[@]} - 1 ))
Total_questions="40"
echo " Total questions:$Total_questions"
c=$(clear)
# Loop through the questions one by one
for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_veeam[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue"
        clear
        echo ' Total 40 questions'

done
clear
echo "End of questions. Thanks for participating"
        ;;

  c)
 QUESTIONS=(
    "What is Veeam primarily used for?|a) Data analytics|b) Data backup and recovery|c) Software development|d) Cloud hosting|b"
    "Which Veeam product is used for virtualized environments?|a) Veeam Backup & Replication|b) Veeam One|c) Veeam Agent|d) Veeam Monitor|a"
    "What is the purpose of Veeam Cloud Connect?|a) Provides cloud-based email|b) Enables offsite backup|c) Manages cloud security|d) Hosts virtual machines|b"
    "Which hypervisors are supported by Veeam Backup & Replication?|a) VMware vSphere|b) Microsoft Hyper-V|c) Both a and b|d) None of the above|c"
    "What does Veeam Backup Copy job do?|a) Duplicates backups to another location|b) Deletes old backups|c) Moves backups to tape storage|d) Compresses backup files|a"
    "Which component manages backup jobs in Veeam?|a) Veeam Backup Proxy|b) Veeam Backup Server|c) Veeam Repository|d) Veeam One|b"
    "What is the function of the Veeam Backup Proxy?|a) Handles data traffic between storage and the backup server|b) Stores backups|c) Encrypts backup data|d) Monitors performance|a"
    "Which Veeam feature allows near-instant VM recovery?|a) SureBackup|b) Instant VM Recovery|c) DataLabs|d) Veeam One|b"
    "How does Veeam ensure backup integrity?|a) Secure Sockets Layer (SSL)|b) SHA-256 Hashing|c) SureBackup verification|d) Redundant Array of Independent Disks (RAID)|c"
    "Which Veeam feature is used to test disaster recovery plans?|a) SureReplica|b) Quick Rollback|c) Snapshot Manager|d) Deduplication|a"
    "What type of storage can be used as a Veeam Backup Repository?|a) Local Disk|b) Network Attached Storage (NAS)|c) Object Storage|d) All of the above|d"
    "Which cloud storage providers are supported by Veeam?|a) AWS S3|b) Azure Blob|c) Google Cloud Storage|d) All of the above|d"
    "What is the role of Veeam ONE?|a) Backup Storage|b) Monitoring and reporting|c) Backup Encryption|d) File-level recovery|b"
    "Which protocol does Veeam use to transfer data between backup proxies and repositories?|a) FTP|b) SMB|c) WAN Acceleration|d) Veeam Data Mover|d"
    "How does Veeam optimize backup storage usage?|a) Compression|b) Deduplication|c) Synthetic Full Backups|d) All of the above|d"
    "What does Veeam Explorer for Microsoft Exchange do?|a) Recovers individual emails and mailboxes|b) Backs up entire Exchange databases|c) Migrates mailboxes to cloud|d) Monitors Exchange servers|a"
    "Which Veeam feature protects against ransomware attacks?|a) Immutable Backups|b) WAN Acceleration|c) Quick Backup|d) Backup Copy Jobs|a"
    "What is Veeam Agent used for?|a) Backing up physical and cloud workloads|b) Virtual machine migration|c) Network security|d) Hypervisor management|a"
    "Which backup type does not require previous backups to restore data?|a) Incremental|b) Differential|c) Full|d) Synthetic Full|c"
    "What is Veeam's Instant File-Level Recovery?|a) Restores entire virtual machines instantly|b) Recovers individual files from a backup|c) Converts VMs to physical machines|d) Encrypts backup files|b"
    "What is Veeam Backup for Microsoft 365 used for?|a) Protecting cloud-hosted Office 365 data|b) Migrating Exchange servers|c) Managing Azure subscriptions|d) Monitoring network traffic|a"
    "Which feature in Veeam allows for direct-to-object storage backup?|a) Object Lock|b) Scale-Out Backup Repository (SOBR)|c) Fast Clone|d) Storage Gateway|b"
    "What is the purpose of Veeam's SureBackup feature?|a) Automatically verifies backup recoverability|b) Encrypts backup data|c) Speeds up data recovery|d) Manages cloud workloads|a"
    "Which type of recovery does Veeam Backup & Replication provide?|a) Full VM recovery|b) File-level recovery|c) Application-item recovery|d) All of the above|d"
    "What is Veeam DataLabs used for?|a) Creating isolated test environments|b) Optimizing WAN transfers|c) Scheduling backups|d) Restoring SQL databases|a"
    "How does Veeam help minimize downtime in disaster recovery scenarios?|a) Snapshots|b) Instant VM Recovery|c) Backup Copy Jobs|d) Storage Migration|b"
    "Which of the following is a common ransomware protection strategy with Veeam?|a) Air-gapped backups|b) Immutable backups|c) Offsite replication|d) All of the above|d"
    "What is the Veeam Backup Validator used for?|a) Checking backup file integrity|b) Deleting old backups|c) Encrypting backup data|d) Compressing backups|a"
    "Which Veeam feature reduces network traffic for remote backups?|a) WAN Acceleration|b) Cloud Connect|c) File-Level Recovery|d) Synthetic Full Backup|a"
    "How does Veeam handle long-term data retention?|a) Tape backup|b) Object storage|c) Cloud archival|d) All of the above|d"
)

SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Veeam MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi

done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Veeam! 🚀"
;;
0) break ;;
*) echo "Invalid option, try again." ;;
    esac
    done
    ;;
 iii)
     while true; do
     echo " You selected devops tools skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " devops_way
     case $devops_way in
 a)
         ## Place code here for rhelvm_question
   clear
# Array of questions
devops_questions=(
'# DevOps Tools Interview Questions

1. What is DevOps?

Answer:

        DevOps is a set of practices that combine software development (Dev) and IT operations (Ops) to improve collaboration and automation.'
'2. What are the key principles of DevOps?

Answer:

       Collaboration, Automation, Continuous Integration, Continuous Deployment, and Monitoring.'
'3. What are some commonly used DevOps tools?

Answer:

      Jenkins, Docker, Kubernetes, Ansible, Terraform, Git, Prometheus, and ELK Stack.'
'4. What is CI/CD?

Answer:

      Continuous Integration (CI) automates code integration, while Continuous Deployment (CD) automates software release.'
'5. What is Infrastructure as Code (IaC)?

Answer:

      IaC is a method of managing and provisioning infrastructure using code-based configuration files.'
'6. What is the role of Jenkins in DevOps?

Answer:

      Jenkins is a CI/CD automation tool used to build, test, and deploy applications.'
'7. How does Docker help in DevOps?

Answer:

      Docker enables containerization, ensuring consistency across development, testing, and production environments.'
'8. What is Kubernetes?

Answer:

      Kubernetes is a container orchestration tool used to manage, scale, and deploy containerized applications.'
'9. How do Ansible and Terraform differ?

Answer:

      Ansible is a configuration management tool, while Terraform is an infrastructure provisioning tool.'
'10. What is GitOps?

Answer:

      GitOps is a DevOps practice that uses Git repositories as the source of truth for managing infrastructure and applications.'
'11. How do you secure a DevOps pipeline?

Answer:

      Implement security scanning tools, enforce access controls, and use secrets management solutions.'
'12. What is Prometheus used for?

Answer:

      Prometheus is a monitoring tool used to collect metrics and generate alerts.'
'13. How does the ELK Stack work?

Answer:

      ELK Stack (Elasticsearch, Logstash, Kibana) is used for logging, data visualization, and analysis.'
'14. What is Helm in Kubernetes?

Answer:

      Helm is a package manager for Kubernetes that simplifies application deployment.'
'15. What is a Blue-Green Deployment?

Answer:

      Blue-Green Deployment is a release strategy that reduces downtime by maintaining two environments (Blue and Green).'
'16. What is the purpose of Service Mesh?

Answer:

      A Service Mesh like Istio manages service-to-service communication, security, and observability.'
'17. What is the difference between a monolithic and microservices architecture?

Answer:

      Monolithic architecture is a single application, while microservices consist of small, independent services.'
'18. How do you handle secrets in DevOps?

Answer:

      Use tools like HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets.'
'19. What is Canary Deployment?

Answer:

      Canary Deployment releases new features to a subset of users before full deployment.'
'20. What is Chaos Engineering?

Answer:

      Chaos Engineering tests system resilience by intentionally introducing failures.'
'21. What is the difference between Continuous Deployment and Continuous Delivery?

Answer:

      Continuous Deployment automatically deploys every change, while Continuous Delivery requires manual approval.'
'22. What is the role of API Gateways in DevOps?

Answer:

      API Gateways manage API traffic, security, and request routing in microservices.'
'23. How does DevSecOps differ from DevOps?

Answer:

      DevSecOps integrates security practices into the DevOps pipeline.'
'24. What is the use of Artifactory in DevOps?

Answer:

      Artifactory is a repository manager for storing and managing software artifacts.'
'25. What are the benefits of using Terraform?

Answer:

      Terraform provides infrastructure automation, version control, and multi-cloud support.'
'26. What is ArgoCD?

Answer:

      ArgoCD is a GitOps tool for continuous delivery of Kubernetes applications.'
'27. How do you monitor microservices?

Answer:

      Use tools like Prometheus, Grafana, and Jaeger for monitoring and tracing.'
'28. What is the role of a Reverse Proxy in DevOps?

Answer:

      A Reverse Proxy improves security, load balancing, and caching for web applications.'
'29. What is a CI/CD pipeline in GitHub Actions?

Answer:

      A GitHub Actions CI/CD pipeline automates build, test, and deployment workflows in GitHub repositories.'
'30. What is OpenShift?

Answer:

      OpenShift is an enterprise Kubernetes platform for application deployment and management.'
'31. What is the function of Nginx in DevOps?

Answer:

      Nginx is used for web serving, reverse proxying, and load balancing.'
'32. What is Spinnaker in DevOps?

Answer:

      Spinnaker is a continuous delivery tool for multi-cloud deployments.'
'33. What is Tekton?

Answer:

      Tekton is a Kubernetes-native CI/CD framework.'
'34. What is the role of Webhooks in CI/CD?

Answer:

      Webhooks trigger automation workflows when changes occur in repositories.'
'35. How do you scale applications in Kubernetes?

Answer:

      Use Horizontal Pod Autoscaler (HPA) or Cluster Autoscaler.'
'36. What is Vault by HashiCorp?

Answer:

      Vault is a tool for securely storing and accessing secrets.'
'37. What is the purpose of Istio?

Answer:

      Istio is a service mesh that manages traffic between microservices.'
'38. What is a Container Registry?

Answer:

      A Container Registry stores and manages container images (e.g., Docker Hub, ECR, GCR).'
'39. What is an SLA in DevOps?

Answer:

      A Service Level Agreement (SLA) defines performance and availability expectations.'
'40. How do you ensure zero downtime deployment?

Answer:

      Use Blue-Green Deployment, Rolling Updates, or Feature Flags.'
)

last_index=$(( ${#devops_questions[@]} - 1 ))
Total_questions="${#devops_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${devops_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

        ;;

  b)
          ## place code here rhelvm_scenario


clear

scenario_devops=(
'# CI/CD (Jenkins, GitHub Actions, GitLab CI/CD, Azure DevOps) – 1 to 10

1 Scenario: Your Jenkins pipeline is taking too long to execute. How do you optimize it?

✔ Answer: Use parallel stages, caching, and optimized Docker images.'

'2 Scenario: A deployment fails, but the previous version was working fine. How do you roll back?

✔ Answer: Use versioned artifacts, Blue-Green deployment, or rollback jobs.'

'3 Scenario: How do you trigger an automatic build in Jenkins when code is pushed to GitHub?

✔ Answer: Configure GitHub Webhooks and Jenkins SCM Polling.'

'4 Scenario: Your GitHub Actions workflow is failing due to missing dependencies. How do you fix it?

✔ Answer: Use caching, proper dependency management, and pinned versions.'

'5 Scenario: How do you secure secrets in a CI/CD pipeline?

✔ Answer: Store them in Jenkins Credentials, GitHub Secrets, or HashiCorp Vault.'

'6 Scenario: How do you prevent accidental deployments to production?

✔ Answer: Use manual approvals and environment-based triggers.'

'7 Scenario: How do you speed up a slow GitLab CI/CD pipeline?

✔ Answer: Use Docker caching, parallel jobs, and optimized test cases.'

'8 Scenario: How do you run different CI/CD jobs based on branch names?

✔ Answer: Use Jenkins conditional build steps or GitHub Actions ‘if’ conditions.'

'9 Scenario: Your team needs to deploy on different cloud providers. How do you manage it?

✔ Answer: Use Terraform, Ansible, or multi-cloud CI/CD pipelines.'

'10 Scenario: How do you ensure consistent builds in your CI/CD pipeline?

✔ Answer: Use immutable infrastructure and fixed versions in dependencies.'

'# Configuration Management (Ansible, Puppet, Chef) – 11 to 20

11 Scenario: You need to provision 100 servers with identical configurations. What tool do you use?

✔ Answer: Use Ansible, Puppet, or Chef.'

'12 Scenario: Your Ansible playbook fails on some servers but succeeds on others. How do you debug?

✔ Answer: Use Ansible verbose mode (-vvv), check inventory and YAML syntax.'

'13 Scenario: How do you prevent configuration drift in infrastructure?

✔ Answer: Use idempotent Ansible/Puppet runs and scheduled compliance checks.'

'14 Scenario: How do you securely store sensitive data in Ansible?

✔ Answer: Use Ansible Vault.'

'15 Scenario: Your team needs to roll out configuration changes gradually. How do you do it?

✔ Answer: Use batch execution in Ansible or canary deployments.'

'16 Scenario: Your Puppet agents are not pulling the latest configuration. How do you fix it?

✔ Answer: Check Puppet server logs, agent connectivity, and force sync.'

'17 Scenario: How do you ensure zero downtime while applying new configurations?

✔ Answer: Use rolling updates and Ansible strategies.'

'18 Scenario: Your Chef cookbook updates are breaking production. How do you test them safely?

✔ Answer: Use Test Kitchen and Chef InSpec.'

'19 Scenario: How do you track configuration changes across environments?

✔ Answer: Use version-controlled playbooks in Git.'

'20 Scenario: How do you automate server patching using Ansible?

✔ Answer: Use Ansible Playbooks with package updates and scheduled jobs.'


'# Containers & Orchestration (Docker, Kubernetes) – 21 to 30

21 Scenario: Your containerized application is failing to start. How do you debug it?

✔ Answer: Check container logs (docker logs), entrypoint errors, and image health.'

'22 Scenario: How do you minimize Docker image size?

✔ Answer: Use multi-stage builds and Alpine base images.'

'23 Scenario: Your Kubernetes pod keeps restarting. How do you troubleshoot?

✔ Answer: Use kubectl describe pod and kubectl logs to check errors.'

'24 Scenario: How do you perform a zero-downtime deployment in Kubernetes?

✔ Answer: Use Rolling Updates or Blue-Green Deployments.'

'25 Scenario: Your Kubernetes cluster is running out of resources. What do you do?

✔ Answer: Optimize resource requests/limits and enable Horizontal Pod Autoscaler.'

'26 Scenario: How do you ensure sensitive data is not exposed in containers?

✔ Answer: Use Kubernetes Secrets or HashiCorp Vault.'

'27 Scenario: Your Dockerized application is consuming too much memory. How do you limit it?

✔ Answer: Set memory limits in Docker Compose or Kubernetes YAML.'

'28 Scenario: You need to restart only one container in a Kubernetes pod. How do you do it?

✔ Answer: Use kubectl delete pod --force (since containers restart with the pod).'

'29 Scenario: How do you troubleshoot a failing Kubernetes ingress rule?

✔ Answer: Check Ingress logs, DNS, and Service exposure.'

'30 Scenario: Your Kubernetes deployment is stuck in Pending state. How do you fix it?

✔ Answer: Check node resources, storage class, and pod scheduling policies.'

'# Cloud & Infrastructure as Code (Terraform, AWS, Azure, GCP) – 31 to 40

31 Scenario: Your Terraform deployment failed. How do you fix it?

✔ Answer: Use terraform plan, check logs, and rollback state if needed.'

'32 Scenario: How do you ensure Terraform deployments are reviewed before applying?

✔ Answer: Use Terraform Cloud or GitHub Actions for validation.'

'33 Scenario: How do you store Terraform state securely?

✔ Answer: Use AWS S3 with DynamoDB locking.'

'34 Scenario: Your AWS Lambda function is failing. How do you troubleshoot?

✔ Answer: Check CloudWatch Logs.'

'35 Scenario: How do you enforce security best practices in the cloud?

✔ Answer: Use CIS benchmarks, AWS Config, or GCP Security Command Center.'

'36 Scenario: Your cloud infrastructure drifted from Terraform configuration. How do you fix it?

✔ Answer: Run terraform plan and reapply changes.'

'37 Scenario: How do you manage secrets in Terraform?

✔ Answer: Use Terraform Vault provider or AWS Secrets Manager.'

'38 Scenario: Your cloud deployment must meet compliance standards. What do you use?

✔ Answer: Use Terraform Sentinel or AWS Config Rules.'

'39 Scenario: Your Terraform apply is stuck. What do you do?

✔ Answer: Check state locks and Terraform Cloud backend.'

'40 Scenario: How do you deploy infrastructure changes with minimal risk?

✔ Answer: Use Canary deployments and Infrastructure as Code validation.'

'# Monitoring & Security (Prometheus, Grafana, ELK, Security) – 41 to 50

41 Scenario: Your application logs are missing. How do you fix it?

✔ Answer: Ensure Log forwarding is configured correctly.'

'42 Scenario: How do you set up monitoring for a microservices architecture?

✔ Answer: Use Prometheus with Grafana dashboards.'

'43 Scenario: Your logs are overwhelming Elasticsearch. How do you optimize it?

✔ Answer: Use Log rotation and Index Lifecycle Policies.'

'44 Scenario: Your Kubernetes cluster has unauthorized access attempts. How do you secure it?

✔ Answer: Enable RBAC, Network Policies, and Audit Logging.'

'45 Scenario: How do you enforce security scanning in your CI/CD pipeline?

✔ Answer: Use Trivy, Snyk, or Docker Security Scanners.'
)

last_index=$(( ${#scenario_devops[@]} - 1 ))


Total_questions="45"
echo " Total questions:$Total_questions"
echo " Press Enter key"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_devops[$i]}"
        echo " "
        echo " "
        read -p ""
        clear
        echo " Total 45 questions"
done
clear
echo " Good ! You visited all questions and answers"

        ;;

  c)

	  QUESTIONS=(
"What is Jenkins used for in DevOps?|a) Configuration management|b) Continuous Integration and Continuous Deployment (CI/CD)|c) Code editing|d) Security monitoring|b"
"Which plugin is used in Jenkins for integrating with GitHub?|a) GitHub Plugin|b) Git Plugin|c) Pipeline Plugin|d) SCM Plugin|a"
"How do you trigger a Jenkins job automatically from GitHub?|a) Poll SCM|b) Webhook integration|c) Manually triggering|d) Email notification|b"
"Which scripting language is used in Jenkins Pipelines?|a) Bash|b) Groovy|c) Python|d) YAML|b"
"What command is used to install Jenkins on a Linux system?|a) apt install jenkins|b) yum install jenkins|c) Both a & b|d) install jenkins|c"
"What is the primary purpose of Docker?|a) Virtualization|b) Containerization|c) Monitoring|d) Load balancing|b"
"Which command lists all Docker containers?|a) docker show containers|b) docker list|c) docker ps -a|d) docker status|c"
"What is the default Docker network mode?|a) Bridge|b) Host|c) None|d) Overlay|a"
"How do you build a Docker image?|a) docker create .|b) docker build -t myimage .|c) docker run myimage|d) docker start build|b"
"What is the purpose of a Dockerfile?|a) It defines environment variables|b) It contains instructions to build an image|c) It manages Docker networks|d) It creates Kubernetes clusters|b"
"What is the main purpose of Kubernetes?|a) Build container images|b) Orchestrate containerized applications|c) Monitor logs|d) Create databases|b"
"What is a Kubernetes pod?|a) A virtual machine|b) A group of one or more containers|c) A network policy|d) A storage volume|b"
"What command is used to check all running pods?|a) kubectl get services|b) kubectl get pods|c) kubectl list pods|d) kubectl pod status|b"
"What is the default scheduler in Kubernetes?|a) Kube-controller|b) Kube-scheduler|c) Kube-apiserver|d) Kubelet|b"
"How do you deploy an application in Kubernetes?|a) kubectl run|b) kubectl apply -f deployment.yaml|c) kubectl create deployment|d) Both b & c|d"
"What is Ansible primarily used for?|a) Continuous Integration|b) Configuration Management|c) Monitoring|d) Log Analysis|b"
"What language is used for writing Ansible playbooks?|a) JSON|b) XML|c) YAML|d) Python|c"
"Which command runs an Ansible playbook?|a) ansible-playbook site.yaml|b) ansible-run site.yaml|c) ansible site.yaml|d) run-ansible site.yaml|a"
"What is the default location of the Ansible inventory file?|a) /etc/ansible/hosts|b) /var/ansible/inventory|c) /opt/ansible/inventory|d) /home/ansible/hosts|a"
"What is the purpose of the ansible.cfg file?|a) Stores variable definitions|b) Defines playbook structure|c) Configures Ansible settings|d) Manages logs|c"
"What is Terraform used for?|a) Configuration management|b) Infrastructure provisioning|c) Continuous integration|d) Logging|b"
"What is the default Terraform file extension?|a) .yml|b) .tf|c) .json|d) .conf|b"
"What command initializes a Terraform project?|a) terraform init|b) terraform plan|c) terraform apply|d) terraform deploy|a"
"How do you apply changes in Terraform?|a) terraform execute|b) terraform run|c) terraform apply|d) terraform commit|c"
"What backend storage can Terraform use?|a) AWS S3|b) Azure Blob Storage|c) Google Cloud Storage|d) All of the above|d"
"What command initializes a Git repository?|a) git init|b) git start|c) git create|d) git repo|a"
"How do you check the status of a Git repository?|a) git check|b) git status|c) git log|d) git commit|b"
"What is the default branch in Git?|a) Main|b) Master|c) Develop|d) Branch1|a"
"What command is used to stage changes in Git?|a) git add .|b) git commit -m message|c) git push|d) git log|a"
"How do you push changes to a remote repository?|a) git send|b) git push origin <branch_name>|c) git update|d) git upload|b"
"What command is used to merge two branches in Git?|a) git combine|b) git join|c) git merge <branch_name>|d) git add-branch|c"
"How do you undo the last Git commit?|a) git revert HEAD|b) git reset --hard HEAD~1|c) git remove HEAD|d) git delete HEAD|b"
"What is Prometheus mainly used for?|a) Infrastructure provisioning|b) Continuous deployment|c) Monitoring and alerting|d) Configuration management|c"
"Which query language is used in Prometheus?|a) SQL|b) JSONPath|c) PromQL|d) YAML|c"
"What is Grafana used for?|a) Code deployment|b) Data visualization and monitoring|c) Running containers|d) CI/CD automation|b"
"What are the components of the ELK stack?|a) Elasticsearch, Logstash, and Kibana|b) Elastic, Linux, Kubernetes|c) Envoy, Logstash, Kafka|d) Elasticsearch, Linux, Kibana|a"
"What tool is used for centralized logging in DevOps?|a) Jenkins|b) Docker|c) Logstash|d) Ansible|c"
"What does CI/CD stand for?|a) Continuous Integration and Continuous Deployment|b) Code Integration and Continuous Delivery|c) Continuous Installation and Continuous Deployment|d) Continuous Infrastructure and Continuous Debugging|a"
"Which tool is NOT a CI/CD tool?|a) Jenkins|b) GitLab CI|c) Terraform|d) CircleCI|c"
"What is the purpose of a pipeline in Jenkins?|a) To create virtual machines|b) To automate the software delivery process|c) To monitor system logs|d) To manage Kubernetes clusters|b"
"What is the default build tool used in a Jenkins pipeline?|a) Gradle|b) Maven|c) Makefile|d) Ant|b"
"What is Infrastructure as Code (IaC)?|a) Writing infrastructure configuration as code|b) Manually provisioning servers|c) Using only physical infrastructure|d) Running applications in VMs|a"
"Which of the following is NOT an Infrastructure as Code (IaC) tool?|a) Terraform|b) Ansible|c) Docker|d) CloudFormation|c"
"What is the main advantage of DevOps?|a) Faster software delivery|b) Increased security risks|c) Higher costs|d) More manual work|a"
"What is the role of a reverse proxy in DevOps?|a) Manage database queries|b) Load balance and route traffic|c) Encrypt data at rest|d) Compile source code|b"
"What is a service mesh used for in Kubernetes?|a) Managing network traffic between services|b) Running CI/CD pipelines|c) Deploying monitoring tools|d) Setting up virtual machines|a"
"Which cloud platform does NOT offer a managed Kubernetes service?|a) AWS|b) Google Cloud|c) Microsoft Azure|d) None of the above|d"
"What is the purpose of AWS Lambda in DevOps?|a) Running applications in containers|b) Automating deployments|c) Running serverless applications|d) Provisioning virtual machines|c"
"What is the main purpose of AWS CloudFormation?|a) Container orchestration|b) Infrastructure as Code (IaC)|c) Logging and monitoring|d) CI/CD automation|b"
"What tool is used to automate cloud infrastructure provisioning?|a) Terraform|b) Git|c) Docker|d) Kubernetes|a"


)
SCORE=0
TOTAL_QUESTIONS=${#QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Devops tools MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Question:$TOTAL_QUESTIONS"
    echo "Total Marks:$SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
         read -p "Press ENTER key to move to the next question"
         clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing devops tool question & answers! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again." ;;
    esac
    done
    ;;
 iv)
     while true; do 
     echo " You selected network_storage_security skill"
     echo " "
     echo " 3 different ways to study this skill"
     echo " ------------------------------------"
     echo " a) Interview Questions "
     echo " b) Scenario based questions "
     echo " c) Exam(quiz)"
     echo " 0) Back to the previous menu"
     echo " "
     read -p "Select your way of study: " basic_way
     case $basic_way in
 a)

       clear
# Array of questions
network_storage_security_questions=(
'# Security, Networking, and Storage Interview Questions (Common for All Platforms)

1. What is the purpose of a firewall?

Answer:

        A firewall is a security device that monitors and controls incoming and outgoing network traffic based on security rules.'
'2. What are the different types of firewalls?

Answer:

        Packet filtering, Stateful inspection, Proxy firewall, Next-generation firewall (NGFW).'
'3. What is the difference between a private and a public IP address?

Answer:

        A private IP address is used within a local network, while a public IP address is assigned by an ISP and accessible over the internet.'
'4. What is the function of a VPN?

Answer:

        A VPN (Virtual Private Network) encrypts internet traffic, ensuring privacy and secure access to remote networks.'
'5. What is the difference between symmetric and asymmetric encryption?

Answer:

        Symmetric encryption uses the same key for encryption and decryption, while asymmetric encryption uses a public-private key pair.'
'6. What is NAT (Network Address Translation)?

Answer:

        NAT translates private IP addresses to public IP addresses for internet access.'
'7. What is RAID, and why is it used?

Answer:

        RAID (Redundant Array of Independent Disks) improves data redundancy and performance in storage solutions.'
'8. What is the difference between RAID 0, RAID 1, and RAID 5?

Answer:

        RAID 0: Striping (no redundancy), RAID 1: Mirroring (redundancy), RAID 5: Striping with parity (balanced redundancy & performance).'
'9. What is the difference between SSD and HDD?

Answer:

        SSDs (Solid State Drives) are faster and have no moving parts, while HDDs (Hard Disk Drives) have mechanical parts and offer larger storage capacity at lower cost.'
'10. What is the role of a load balancer?

Answer:

        A load balancer distributes network traffic across multiple servers to improve performance and reliability.'
'11. What is the OSI model, and what are its layers?

Answer:

        The OSI model is a framework that standardizes network communication into seven layers: Physical, Data Link, Network, Transport, Session, Presentation, and Application.'
'12. What is the difference between TCP and UDP?

Answer:

        TCP (Transmission Control Protocol) is connection-oriented and reliable, while UDP (User Datagram Protocol) is connectionless and faster but less reliable.'
'13. What is an IDS and an IPS?

Answer:

        IDS (Intrusion Detection System) detects malicious activity, while IPS (Intrusion Prevention System) blocks threats in real-time.'
'14. What is the purpose of port numbers in networking?

Answer:

        Port numbers help identify specific services and applications running on a system (e.g., HTTP uses port 80, HTTPS uses port 443).'
'15. How does DNS work?

Answer:

        DNS (Domain Name System) translates domain names into IP addresses to facilitate internet communication.'
'16. What is the difference between NTFS, FAT32, and exFAT?

Answer:

        NTFS: Supports large files and security features, FAT32: Compatible but has a 4GB file size limit, exFAT: Supports large files and works across different OS.'
'17. How does multi-factor authentication (MFA) enhance security?

Answer:

        MFA requires multiple verification methods (password + OTP or biometrics), increasing security against unauthorized access.'
'18. What are common storage security threats?

Answer:

        Ransomware, unauthorized access, data corruption, and hardware failure.'
'19. What is ARP (Address Resolution Protocol)?

Answer:

        ARP resolves IP addresses to MAC addresses for local network communication.'
'20. What is DHCP, and how does it work?

Answer:

        DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses to devices in a network.'
'21. What is Zero Trust Security?

Answer:

        Zero Trust assumes no device or user is trusted by default and enforces strict access controls.'
'22. What is the difference between block storage and object storage?

Answer:

        Block storage divides data into blocks for high performance, while object storage manages data as objects with metadata for scalability.'
'23. What is a subnet mask?

Answer:

        A subnet mask separates the network and host portions of an IP address.'
'24. How do you secure a Wi-Fi network?

Answer:

        Use WPA2/WPA3 encryption, strong passwords, disable WPS, and update firmware regularly.'
'25. What is a Man-in-the-Middle (MITM) attack?

Answer:

        A MITM attack intercepts communication between two parties to eavesdrop or manipulate data.'
'26. What is the difference between SAN and NAS?

Answer:

        SAN (Storage Area Network) provides high-speed block-level storage, while NAS (Network Attached Storage) provides file-based storage over a network.'
'27. How does HTTPS secure web traffic?

Answer:

        HTTPS encrypts data using SSL/TLS to prevent eavesdropping and tampering.'
'28. What is the difference between backup and disaster recovery?

Answer:

        Backup involves creating copies of data, while disaster recovery includes restoring systems after a failure.'
'29. What is the principle of least privilege?

Answer:

        Users and systems should have only the minimum access needed to perform their tasks.'
'30. What is endpoint security?

Answer:

        Endpoint security protects devices like laptops, desktops, and mobile phones from cyber threats using antivirus, firewalls, and encryption.'
)

last_index=$(( ${#network_storage_security_questions[@]} - 1 ))
Total_questions="${#network_storage_security_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${network_storage_security_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
done

clear
echo " End of questions. Thanks for participating!"

        ;;

  b)
        clear

# Array of scenario-based questions for Networking, Storage, and Security
scenario_questions=(
"1. Scenario: A user is locked out of their account. How do you resolve this?
Answer:
- Reset the password or unlock the account in Active Directory \(Windows\) or use 'passwd' command in Linux.
- Verify if the user has reached login attempt limits.
- Check system logs for suspicious activity."

"2. Scenario: You need to securely transfer files between two remote servers. What options do you have?
Answer:
- Use SCP \(Secure Copy\) or SFTP for encrypted transfer.
- Configure SSH key-based authentication for secure login.
- Consider using VPN for additional security."

"3. Scenario: A web application is running slow. What could be the issue?
Answer:
- Check server load and optimize database queries.
- Optimize images, enable caching, and use a Content Delivery Network \(CDN\).
- Review network latency and firewall rules."

"4. Scenario: A firewall rule is blocking a legitimate service. How do you safely allow it?
Answer:
- Verify the service IP and port requirements.
- Modify firewall rules carefully to avoid security risks.
- Apply changes in a test environment before deploying to production."

"5. Scenario: A database server is experiencing frequent crashes. What could be the cause and solution?
Answer:
- Check system logs for memory or disk errors.
- Optimize database queries and indexing.
- Increase system resources or scale out the database setup."

"6. Scenario: You need to back up critical data securely. What approach do you use?
Answer:
- Use automated backup solutions like rsync or cloud backup services.
- Encrypt backups before storage.
- Store backups in multiple locations for redundancy."

"7. Scenario: A network user reports frequent disconnections. How do you troubleshoot?
Answer:
- Check for interference \(Wi-Fi\) or faulty cables.
- Verify DHCP lease issues.
- Inspect router logs and update firmware."

"8. Scenario: A server is running out of disk space. What steps should you take?
Answer:
- Delete unnecessary log files and temporary files.
- Move large files to an external or network-attached storage \(NAS\).
- Extend the disk partition or add a new disk."

"9. Scenario: A security audit found open ports on a server. How do you address this?
Answer:
- Use 'netstat' or 'ss' command to list open ports.
- Close unnecessary ports using firewall rules.
- Apply security patches and review application settings."

"10. Scenario: A user lost access to an encrypted file. How can you recover it?
Answer:
- Check if the user has a backup or recovery key.
- Verify permissions and ownership settings.
- Use decryption tools if a key exists."

"11. Scenario: Your website is under a DDoS attack. How do you mitigate the impact?
Answer:
- Use a Content Delivery Network \(CDN\) to absorb traffic.
- Enable rate-limiting and Web Application Firewall \(WAF\).
- Identify and block malicious IPs using firewall rules."

"12. Scenario: A network admin notices unusual outbound traffic from a server. What could be happening?
Answer:
- The server may be infected with malware or compromised.
- Analyze network traffic logs and run security scans.
- Isolate the server from the network and apply security patches."

"13. Scenario: A user reports that emails are being marked as spam. What should you check?
Answer:
- Verify SPF, DKIM, and DMARC records for email authentication.
- Check for blacklisted IP addresses.
- Ensure that email servers are properly configured."

"14. Scenario: Your VPN connection keeps dropping. What troubleshooting steps would you take?
Answer:
- Check for network stability and firewall rules.
- Update VPN client software and verify authentication settings.
- Try switching to a different VPN protocol \(e.g., OpenVPN, IKEv2\)."

"15. Scenario: A user reports that they cannot access a shared network folder. What should you check?
Answer:
- Verify that the user has the correct permissions.
- Check if the network share is online and reachable.
- Inspect access logs for potential security issues."

"16. Scenario: A server suddenly starts consuming 100% CPU. What do you do?
Answer:
- Use 'top' or 'Task Manager' to identify resource-hungry processes.
- Restart non-essential services and check for malware.
- Analyze logs to find any ongoing attacks or misconfigurations."

"17. Scenario: A company needs to ensure employees use strong passwords. How do you enforce this?
Answer:
- Implement password policies via Group Policy \(Windows\) or PAM \(Linux\).
- Enforce multi-factor authentication \(MFA\).
- Conduct regular security awareness training."

"18. Scenario: Your company needs to store sensitive data securely. What best practices should you follow?
Answer:
- Encrypt data at rest and in transit.
- Use access control policies to restrict sensitive data access.
- Regularly audit data access logs."

"19. Scenario: A user reports slow internet browsing. How do you diagnose the issue?
Answer:
- Test speed using 'ping' or 'traceroute' commands.
- Check browser extensions and clear cache.
- Inspect firewall rules and proxy settings."

"20. Scenario: Your company wants to prevent USB storage device access. How do you implement this?
Answer:
- Disable USB ports via Group Policy \(Windows\) or Udev rules \(Linux\).
- Implement Data Loss Prevention \(DLP\) software.
- Log and monitor device connection attempts."

"21. Scenario: A server is experiencing high disk I/O. How do you investigate?
Answer:
- Use 'iostat' or 'iotop' to monitor disk activity.
- Check if swap space is being overused.
- Optimize disk read/write operations and consider SSD upgrades."

"22. Scenario: A user reports their credentials are being used without permission. What steps should you take?
Answer:
- Immediately revoke access and force a password reset.
- Review login history and check for suspicious IPs.
- Enable MFA to prevent unauthorized access."

"23. Scenario: A file server is running out of storage. What solutions can you implement?
Answer:
- Move infrequently accessed files to an archive storage.
- Implement disk quotas to limit excessive usage.
- Set up automatic file compression or deduplication."

"24. Scenario: Your web application logs show multiple failed login attempts. What should you do?
Answer:
- Implement account lockout policies after multiple failed attempts.
- Enable CAPTCHA verification for login pages.
- Block repeated login attempts from suspicious IPs."

"25. Scenario: Your organization's network is expanding. How do you ensure scalability and security?
Answer:
- Implement VLANs to segment network traffic.
- Use firewalls and Intrusion Detection Systems \(IDS\).
- Regularly update network configurations and security policies."

"26. Scenario: A company wants to ensure its cloud storage data is protected. What steps should they take?
Answer:
- Enable encryption for cloud storage.
- Use role-based access control \(RBAC\).
- Set up automated backups and versioning."

"27. Scenario: A developer accidentally pushed secrets to a public repository. How do you mitigate the risk?
Answer:
- Remove the secrets and rotate exposed credentials.
- Use tools like 'git-secrets' to prevent future incidents.
- Audit repository access logs for unauthorized access."

"28. Scenario: Your company's firewall logs show frequent brute-force attacks. What measures should be taken?
Answer:
- Implement fail2ban or firewall rules to block repeated attempts.
- Use MFA and strong password policies.
- Review logs to identify patterns and possible attackers."

"29. Scenario: Your company wants to monitor all network traffic for anomalies. What tools can be used?
Answer:
- Deploy network monitoring tools like Wireshark, Zeek, or Suricata.
- Set up Security Information and Event Management \(SIEM\).
- Analyze traffic patterns using AI-based anomaly detection."

"30. Scenario: Your organization needs to ensure all employees' devices are updated. What is the best approach?
Answer:
- Enforce patch management policies via MECM, WSUS, or Ansible.
- Enable automatic updates for all endpoints.
- Conduct regular security audits to verify compliance."
)

Total_questions="${#scenario_questions[@]}"
echo "Total questions: $Total_questions"

for question in "${scenario_questions[@]}"; do
    echo -e "\n$question\n"
    read -p "Press Enter key to continue..."
    clear
done

clear
echo "End of questions. Thanks for participating!"
	  
	  ;;

  c)
       
COMMON_QUESTIONS=(
    "Which protocol is used for secure remote login?|a) FTP|b) SSH|c) Telnet|d) SMTP|b"
    "Which encryption method is commonly used to secure files?|a) MD5|b) AES|c) SHA-256|d) CRC32|b"
    "Which layer of the OSI model handles IP addressing?|a) Application|b) Network|c) Transport|d) Data Link|b"
    "Which command is used to check network connectivity?|a) ping|b) ls|c) grep|d) chmod|a"
    "Which tool is commonly used for network packet analysis?|a) Wireshark|b) Notepad|c) Task Manager|d) Registry Editor|a"
    "Which protocol is used for encrypted web traffic?|a) HTTP|b) HTTPS|c) FTP|d) Telnet|b"
    "What is the default port number for SSH?|a) 21|b) 22|c) 80|d) 443|b"
    "Which storage type is volatile and loses data when power is off?|a) SSD|b) RAM|c) HDD|d) Tape Backup|b"
    "Which command is used to view disk usage in Linux?|a) du|b) df|c) lsblk|d) fdisk|b"
    "Which file system is commonly used in Windows?|a) NTFS|b) ext4|c) APFS|d) FAT32|a"
    "Which protocol is used for sending emails?|a) SMTP|b) HTTP|c) SNMP|d) FTP|a"
    "Which firewall type inspects incoming and outgoing traffic?|a) Stateful|b) Stateless|c) Proxy|d) NAT|a"
    "Which storage system is best for large-scale cloud storage?|a) RAID 0|b) SAN|c) NAS|d) Object Storage|d"
    "What is the main purpose of a VPN?|a) Speed up the internet|b) Encrypt network traffic|c) Reduce power consumption|d) Increase CPU performance|b"
    "Which of the following is a strong password example?|a) password123|b) qwerty|c) P@ssw0rd!2024|d) admin|c"
    "What is the function of RAID 1?|a) Striping|b) Mirroring|c) Parity|d) Compression|b"
    "Which port does DNS use?|a) 53|b) 25|c) 443|d) 110|a"
    "Which tool is used to check open ports on a system?|a) netstat|b) ls|c) chmod|d) grep|a"
    "Which layer of security protects against malware infections?|a) Firewall|b) Antivirus|c) Network Monitor|d) VPN|b"
    "Which of the following is a cloud-based storage service?|a) OneDrive|b) VirtualBox|c) Nmap|d) BitLocker|a"
    "Which command is used to check the current network configuration in Windows?|a) ifconfig|b) ipconfig|c) netstat|d) traceroute|b"
    "Which command is used to change file permissions in Linux?|a) chmod|b) cp|c) mv|d) ls|a"
    "Which protocol is used to securely transfer files over a network?|a) FTP|b) HTTP|c) SFTP|d) Telnet|c"
    "Which storage type is best for quick access speeds?|a) HDD|b) SSD|c) Tape Drive|d) Floppy Disk|b"
    "Which encryption method is used in Wi-Fi security?|a) WPA2|b) SHA-256|c) MD5|d) TLS|a"
    "Which command is used to display running processes in Linux?|a) ls|b) ps|c) top|d) chmod|c"
    "What does the ‘ping’ command test?|a) Disk speed|b) Network connectivity|c) CPU usage|d) File integrity|b"
    "Which tool is used to trace the path packets take across a network?|a) ping|b) traceroute|c) netstat|d) lsblk|b"
    "Which storage system allows multiple users to access the same data simultaneously?|a) RAID 5|b) NAS|c) RAM|d) External HDD|b"
    "Which security measure helps prevent unauthorized access to a system?|a) Strong passwords|b) Open ports|c) Running old software|d) Disabling firewalls|a"
)

SCORE=0
TOTAL_QUESTIONS=${#COMMON_QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Security, Networking & Storage MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!COMMON_QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${COMMON_QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Questions: $TOTAL_QUESTIONS"
    echo "Score: $SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Security, Networking & Storage! 🚀"
;;

0) break ;;
*) echo " Invalid option. Try again." ;;
 esac
 done
;;
0) break ;;
*) echo "Invalid option. Try again." ;;

esac

done
;;

 5)
              while true; do
              echo "i)   AWS"
              echo "ii)  GCP"
              echo "iii) Azure"
              echo "  0) Back to the main menu"
              echo " "
                read -p "Select skill:🎯 " cloud_skill
                clear
                case $cloud_skill in

                        i)      
                                while true; do
                                echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"
                                echo " "
                                       read -p "Select your way of study: " aws_way
                                       case $aws_way in


     a)
clear
# Array of questions
aws_questions=(
'# AWS Interview Questions

1. What is AWS?

Answer:

        AWS (Amazon Web Services) is a cloud computing platform offering infrastructure, platform, and software services on a pay-as-you-go basis.'
'2. What are the key services in AWS?

Answer:

       EC2, S3, RDS, Lambda, VPC, IAM, CloudFormation, CloudWatch, and more.'
'3. How do you create an EC2 instance?

Answer:

      AWS Console -> EC2 Dashboard -> Launch Instance -> Select AMI, Instance Type, and Configure Settings.'
'4. What is IAM in AWS?

Answer:

      IAM (Identity and Access Management) is a service that helps manage access to AWS resources securely.'
'5. How do you store and retrieve data in S3?

Answer:

      Use AWS CLI:
      aws s3 cp file.txt s3://my-bucket/
      aws s3 cp s3://my-bucket/file.txt .'
'6. What is an AWS VPC?

Answer:

      A Virtual Private Cloud (VPC) allows you to create an isolated network within AWS.'
'7. How do you monitor AWS resources?

Answer:

      Use CloudWatch to collect and track metrics, logs, and set up alarms.'
'8. What is an AWS Security Group?

Answer:

      Security Groups act as virtual firewalls that control inbound and outbound traffic to AWS resources.'
'9. What is Auto Scaling in AWS?

Answer:

      Auto Scaling automatically adjusts the number of instances based on demand to ensure application availability.'
'10. How do you set up an AWS Lambda function?

Answer:

      AWS Console -> Lambda -> Create Function -> Choose Runtime -> Upload Code -> Configure Triggers.'
'11. What is an Elastic Load Balancer (ELB)?

Answer:

      ELB distributes incoming traffic across multiple targets to ensure high availability.'
'12. How do you create an RDS instance?

Answer:

      AWS Console -> RDS -> Create Database -> Choose Engine -> Configure Settings -> Launch Instance.'
'13. What is AWS Route 53?

Answer:

      Route 53 is a scalable Domain Name System (DNS) web service.'
'14. How do you secure an AWS account?

Answer:

      Enable MFA, Use IAM roles, Follow the Principle of Least Privilege, and Enable CloudTrail logging.'
'15. What is AWS CloudFormation?

Answer:

      CloudFormation allows you to provision AWS infrastructure using code templates.'
'16. What is an AWS EBS volume?

Answer:

      Elastic Block Store (EBS) provides persistent block storage for EC2 instances.'
'17. How do you back up data in AWS?

Answer:

      Use AWS Backup, S3 Versioning, or RDS Snapshots.'
'18. What is an AWS Elastic Beanstalk?

Answer:

      Elastic Beanstalk is a Platform-as-a-Service (PaaS) that simplifies application deployment.'
'19. How do you set up AWS CloudTrail?

Answer:

      AWS Console -> CloudTrail -> Create Trail -> Choose Storage -> Enable Logging.'
'20. What is AWS Glue?

Answer:

      AWS Glue is a fully managed ETL (Extract, Transform, Load) service for data preparation.'
'21. How do you configure a NAT Gateway?

Answer:

      AWS Console -> VPC -> NAT Gateways -> Create NAT Gateway -> Attach to Subnet.'
'22. What is an AWS SNS topic?

Answer:

      Simple Notification Service (SNS) allows message publishing to multiple subscribers.'
'23. How do you automate tasks in AWS?

Answer:

      Use AWS Lambda, Step Functions, or CloudWatch Events.'
'24. What is AWS Fargate?

Answer:

      AWS Fargate allows you to run containers without managing servers.'
'25. How do you enforce compliance in AWS?

Answer:

      Use AWS Config, GuardDuty, and Security Hub.'
'26. What is AWS Cost Explorer?

Answer:

      AWS Cost Explorer helps track and forecast AWS spending.'
'27. How do you configure AWS Multi-Factor Authentication (MFA)?

Answer:

      AWS Console -> IAM -> Users -> Security Credentials -> Enable MFA.'
'28. What is an AWS Direct Connect?

Answer:

      Direct Connect provides a dedicated network connection from on-premises to AWS.'
'29. How do you scale a database in AWS?

Answer:

      Use RDS Read Replicas or Amazon Aurora Auto Scaling.'
'30. What is AWS Systems Manager?

Answer:

      AWS Systems Manager helps automate and manage infrastructure at scale.'
)

last_index=$(( ${#aws_questions[@]} - 1 ))
Total_questions="${#aws_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${aws_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

;;

b)

clear
scenario_aws=(
'#Compute (EC2, Lambda, Auto Scaling) - 1 to 10

1. Scenario: Your EC2 instance suddenly stops responding. How do you troubleshoot?

✔ Answer:

 Check instance status checks, verify system logs, check security groups & NACLs, and try rebooting the instance.'

'2 Scenario: Your application is receiving unexpected traffic spikes. How do you handle this automatically?

✔ Answer:

 Use Auto Scaling with Elastic Load Balancer (ELB) to distribute traffic and scale up instances.'

'3 Scenario: A developer wants to run a script periodically without maintaining an EC2 instance. What AWS service should they use?

✔ Answer:

 Use AWS Lambda with Amazon EventBridge (CloudWatch Events) to trigger the script at scheduled intervals.'

'4 Scenario: Your EC2 instance keeps failing due to high memory usage. How do you monitor and fix it?

✔ Answer:

 Enable CloudWatch memory metrics using the CloudWatch Agent and upgrade the instance type if needed.'

'5 Scenario: How can you ensure your EC2 instance data persists even after termination?

✔ Answer:

 Use an EBS volume with Delete on Termination disabled or store data in S3/RDS instead.'

'6 Scenario: You need to securely SSH into your EC2 instance without managing SSH keys. What AWS service do you use?

✔ Answer:

 Use AWS Systems Manager Session Manager to access the instance securely.'

'7 Scenario: A new EC2 instance is unable to access the internet. What could be wrong?

✔ Answer:

 Check if the instance has a public IP, correct route table settings, and internet gateway (IGW) attached.'

'8 Scenario: Your application is running on EC2, but customers in another region experience high latency. How do you fix this?

✔ Answer:

 Deploy instances in multiple AWS Regions and use AWS Global Accelerator or Route 53 latency-based routing.'

'9 Scenario: Your EC2 instance was terminated unexpectedly. How do you investigate the cause?

✔ Answer:

 Check AWS CloudTrail logs for termination events, review Auto Scaling policies, and check instance health status.'

'10 Scenario: You need to move a running EC2 instance to another Availability Zone. How do you do it?

✔ Answer:

 Create an AMI of the instance, launch a new instance from the AMI in the target AZ, and update DNS records.'

#Storage (S3, EBS, EFS, Glacier) - 11 to 20

'11 Scenario: Your S3 bucket is publicly accessible. How do you restrict access?

✔ Answer:

 Use S3 bucket policies, IAM roles, and block public access settings.'

'12 Scenario: Your S3 files need to be encrypted at rest and in transit. How do you configure this?

✔ Answer:

 Use S3 default encryption (SSE-S3 or SSE-KMS) and enforce HTTPS for S3 access.'

'13 Scenario: You need to share large S3 files with external users without making them public. What do you use?

✔ Answer:

 Generate pre-signed URLs with expiration times.'

'14 Scenario: How do you reduce S3 storage costs for infrequently accessed data?

✔ Answer:

 Use S3 Lifecycle Policies to move data to S3 Infrequent Access (IA) or Glacier.'

'15 Scenario: An application running on EC2 needs shared storage for multiple instances. What AWS storage service do you use?

✔ Answer:

 Use Amazon EFS for shared file storage across multiple EC2 instances.'

'16 Scenario: Your S3 bucket needs to sync data between different AWS regions. What feature do you use?

✔ Answer:

 Enable S3 Cross-Region Replication (CRR).'

'17 Scenario: Your EBS volume is full. How do you increase its size?

✔ Answer:

 Modify the volume size in AWS Console, then resize the filesystem using OS commands (resize2fs for Linux).'

'18 Scenario: Your S3 files were accidentally deleted. How do you recover them?

✔ Answer:

 Use S3 Versioning and restore files from previous versions.'

'19 Scenario: You need to store regulatory archives for 10 years at the lowest cost. What storage option do you choose?

✔ Answer:

 Use S3 Glacier Deep Archive with lifecycle policies.'

'20 Scenario: A user needs read-only access to a specific S3 bucket. How do you grant it?

✔ Answer:

 Create an IAM policy with s3:GetObject permission for that bucket.'

# Networking & Security (VPC, IAM, Security) - 21 to 30

'21 Scenario: Your private EC2 instances need internet access. How do you configure it?

✔ Answer:

 Use a NAT Gateway in a public subnet.'

'22 Scenario: How do you create a secure, encrypted connection between your data center and AWS?

✔ Answer:

 Use AWS Site-to-Site VPN or AWS Direct Connect.'

'23 Scenario: You need to restrict SSH access to EC2 instances to your office IP only. How do you do it?

✔ Answer:

 Modify the security group to allow SSH (port 22) only from your offices public IP.'

'24 Scenario: How do you enforce MFA for AWS console users?

✔ Answer:

 Enable MFA in IAM settings.'

'25 Scenario: Your AWS resources were accessed from an unauthorized IP. How do you investigate?

✔ Answer:

 Check AWS CloudTrail logs for suspicious activity.'

'26 Scenario: Your AWS keys are leaked. What’s the first step you take?

✔ Answer:

 Deactivate compromised keys, create new ones, and review CloudTrail logs.'

'27 Scenario: Your database needs to be securely accessible only to your application servers. How do you configure this?

✔ Answer:

 Place the database in a private subnet and allow access via security groups.'

'28 Scenario: How do you set up a custom domain name for an AWS application?

✔ Answer:

 Use Route 53 to create a hosted zone and configure DNS records.'

'29 Scenario: Your VPC needs secure communication between two AWS regions. What do you use?

✔ Answer:

 Use VPC Peering or AWS Transit Gateway.'

'30 Scenario: You need to allow multiple teams to access different AWS services with different permissions. How do you manage this?

✔ Answer:

 Use IAM roles & policies to grant least privilege access.'

# Database & Serverless (RDS, DynamoDB, Lambda) - 31 to 40

'31 Scenario: Your RDS database is running slow. How do you troubleshoot?

✔ Answer:

 Check RDS Performance Insights, optimize queries, and scale RDS instance type.'

'32 Scenario: You need to back up your RDS database automatically. What do you do?

✔ Answer:

 Enable automated backups and configure manual snapshots.'

'33 Scenario: How do you make an RDS database highly available?

✔ Answer:

 Enable Multi-AZ Deployment.'

'34 Scenario: Your Lambda function is running longer than expected. How do you optimize it?

✔ Answer:

 Increase memory allocation, optimize code execution, and use Lambda@Edge for caching.'

'35 Scenario: Your DynamoDB table is experiencing high read latency. What do you do?

✔ Answer:

 Enable DynamoDB Accelerator (DAX) for caching.'
)

last_index=$((${#scenario_aws[@]} - 1 ))
Total_questions="35"
echo " Total questions:$Total_questions"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_aws[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo " Total 35 questions"
done
clear
echo "End of questions. Thanks for participating"

        ;;

c)

aws_quiz=(
    "Which AWS service provides compute capacity in the cloud?|a) S3|b) EC2|c) RDS|d) Lambda|b"
    "What is the main function of S3?|a) Compute services|b) Object storage|c) Database hosting|d) Serverless functions|b"
    "Which AWS service is used for managing access and permissions?|a) IAM|b) S3|c) EC2|d) CloudFront|a"
    "What does AWS Lambda allow you to do?|a) Run servers 24/7|b) Run code without managing servers|c) Manage databases|d) Automate networking|b"
    "Which AWS database service is fully managed and supports SQL?|a) DynamoDB|b) RDS|c) S3|d) Redshift|b"
    "What is the default storage class in S3?|a) Glacier|b) Intelligent-Tiering|c) Standard|d) Infrequent Access|c"
    "Which AWS service helps distribute traffic across multiple instances?|a) Route 53|b) Load Balancer|c) CloudWatch|d) CloudTrail|b"
    "How do you restrict access to an S3 bucket?|a) Security Groups|b) IAM Policies|c) VPC Peering|d) EC2 Roles|b"
    "Which AWS service is used for event-driven messaging between microservices?|a) S3|b) SNS|c) CloudFront|d) SQS|d"
    "What is the primary function of AWS CloudFormation?|a) Automating infrastructure deployment|b) Monitoring applications|c) Managing user identities|d) Running databases|a"
    "Which AWS service is used to track API calls?|a) AWS Config|b) CloudTrail|c) CloudWatch|d) IAM|b"
    "Which AWS service allows you to create private networks?|a) Route 53|b) VPC|c) IAM|d) CloudFront|b"
    "Which AWS database is NoSQL-based?|a) RDS|b) DynamoDB|c) Redshift|d) Aurora|b"
    "What is the main function of AWS Auto Scaling?|a) To increase security|b) To adjust resources based on demand|c) To store logs|d) To deploy applications|b"
    "Which AWS service provides managed Kubernetes?|a) ECS|b) Lambda|c) EKS|d) CloudFormation|c"
    "What is the use of AWS Route 53?|a) File storage|b) Domain Name System (DNS) service|c) Load balancing|d) Data encryption|b"
    "Which service can help reduce latency for globally distributed users?|a) CloudFront|b) S3|c) IAM|d) VPC|a"
    "Which AWS service is a fully managed container orchestration service?|a) ECS|b) Lambda|c) S3|d) CloudFormation|a"
    "Which service helps monitor AWS infrastructure and applications?|a) CloudTrail|b) CloudWatch|c) IAM|d) SNS|b"
    "What does AWS Elastic Beanstalk do?|a) Manages EC2 instances|b) Simplifies app deployment|c) Stores objects|d) Controls network security|b"
    "Which service is used to manage encryption keys in AWS?|a) KMS|b) IAM|c) S3|d) EC2|a"
    "Which AWS database is a data warehouse solution?|a) DynamoDB|b) RDS|c) Redshift|d) Aurora|c"
    "What is AWS Direct Connect used for?|a) Connecting private networks to AWS|b) Encrypting network traffic|c) Storing logs|d) Running machine learning models|a"
    "Which AWS service helps migrate databases to AWS?|a) DMS|b) EC2|c) VPC|d) Route 53|a"
    "Which AWS service allows you to deploy and manage serverless applications?|a) Lambda|b) CloudFormation|c) EC2|d) S3|a"
    "What is AWS WAF used for?|a) Protecting web applications from attacks|b) Managing IAM permissions|c) Encrypting data|d) Managing databases|a"
    "Which AWS service provides a fully managed GraphQL API?|a) Lambda|b) AppSync|c) CloudFront|d) IAM|b"
    "Which AWS service provides a content delivery network (CDN)?|a) CloudFront|b) EC2|c) RDS|d) S3|a"
    "Which AWS service is best for storing and retrieving secrets like database passwords?|a) AWS Secrets Manager|b) IAM|c) S3|d) Lambda|a"
    "Which AWS service provides a managed Apache Kafka service?|a) Amazon MSK|b) DynamoDB|c) Lambda|d) IAM|a")

SCORE=0
TOTAL_QUESTIONS=${#aws_quiz[@]}

clear
echo "================================="
echo "🔥 AWS MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!aws_quiz[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${aws_quiz[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Questions: $TOTAL_QUESTIONS"
    echo "Score: $SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering AWS! 🚀"
;;

0) break ;;
*) echo "Invalid option try again." ;;

esac

done

;;

 ii)
     while true; do 
 ## GCP interview questions:
 echo " "
 echo " You selected bash skill"
 echo " "
 echo " 3 different ways to study this skill"
 echo " ------------------------------------"
 echo " a) Interview Questions"
 echo " b) Scenario based questions"
 echo " c) Exam(quiz)"
 echo " 0) Back to the previous menu"
 echo " "
 read -p "Select your way of study: " bash_way
 case $bash_way in

 a)


clear
# Array of questions
gcp_questions=(
'# GCP Interview Questions

1. What is Google Cloud Platform (GCP)?

Answer:

        GCP is a suite of cloud computing services offered by Google that runs on the same infrastructure used by Google products like Search, Gmail, and YouTube.'
'2. What are the key services provided by GCP?

Answer:

        Compute Engine, Kubernetes Engine, Cloud Storage, BigQuery, Cloud Functions, Cloud Run, and Cloud SQL.'
'3. How do you create a virtual machine in GCP?

Answer:

        Go to GCP Console -> Compute Engine -> VM Instances -> Create Instance.'
'4. What is a GCP project?

Answer:

        A GCP project is a container for resources and services, with settings like billing, permissions, and APIs.'
'5. How do you authenticate GCP services?

Answer:

        Using Service Accounts, OAuth 2.0, or API keys.'
'6. What is Google Kubernetes Engine (GKE)?

Answer:

        A managed Kubernetes service that allows you to run containerized applications on GCP.'
'7. How do you deploy an application on GKE?

Answer:

        Create a Kubernetes cluster -> Deploy using kubectl -> Expose the deployment using a service.'
'8. What is Cloud Storage in GCP?

Answer:

        A scalable, durable object storage service used for storing unstructured data.'
'9. What are storage classes in GCP Cloud Storage?

Answer:

        Standard, Nearline, Coldline, and Archive.'
'10. How do you manage IAM permissions in GCP?

Answer:

        Assign roles to users, groups, or service accounts using the IAM policy framework.'
'11. What is BigQuery?

Answer:

        A serverless, highly scalable data warehouse for analyzing large datasets.'
'12. How do you run a SQL query in BigQuery?

Answer:

        Use the BigQuery Console, bq command-line tool, or REST API.'
'13. What is Cloud Functions?

Answer:

        A serverless execution environment for running event-driven functions.'
'14. How do you trigger a Cloud Function?

Answer:

        Via HTTP request, Cloud Pub/Sub, Cloud Storage events, or Firestore changes.'
'15. What is Cloud Run?

Answer:

        A managed platform for running containerized applications with automatic scaling.'
'16. What is a VPC in GCP?

Answer:

        A virtual private cloud that provides networking capabilities for GCP resources.'
'17. How do you create a VPC?

Answer:

        Use GCP Console -> VPC network -> Create VPC.'
'18. What is Cloud SQL?

Answer:

        A managed relational database service supporting MySQL, PostgreSQL, and SQL Server.'
'19. How do you connect to a Cloud SQL instance?

Answer:

        Use Cloud SQL Proxy, authorized networks, or private IP addresses.'
'20. What is Cloud Spanner?

Answer:

        A fully managed, scalable, globally distributed relational database service.'
'21. How do you monitor resources in GCP?

Answer:

        Use Cloud Monitoring and Cloud Logging.'
'22. What is Cloud Pub/Sub?

Answer:

        A messaging service for event-driven systems and real-time data streaming.'
'23. What is Terraform and how does it work with GCP?

Answer:

        Terraform is an infrastructure-as-code tool used to manage GCP resources declaratively.'
'24. What is Cloud Identity and Access Management (IAM)?

Answer:

        A system for managing permissions across GCP resources.'
'25. What is Google Cloud Interconnect?

Answer:

        A dedicated network connection between on-premises infrastructure and GCP.'
'26. What is Google Cloud CDN?

Answer:

        A global content delivery network for caching and delivering web content.'
'27. How do you automate deployments in GCP?

Answer:

        Using Cloud Build, Deployment Manager, or Terraform.'
'28. What is Google Cloud Dataproc?

Answer:

        A managed Hadoop and Spark service for big data processing.'
'29. What is Google Cloud Dataflow?

Answer:

        A fully managed service for stream and batch data processing using Apache Beam.'
'30. What is Google Cloud Anthos?

Answer:

        A hybrid and multi-cloud platform for managing Kubernetes workloads across environments.'
)

last_index=$(( ${#gcp_questions[@]} - 1 ))
Total_questions="${#gcp_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${gcp_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

;;

b)

        clear

scenario_gcp=(

'# Compute (GCE, GKE, App Engine, Cloud Run) - 1 to 10

1 Scenario: Your GCP VM (Compute Engine) is running slow. How do you troubleshoot?

✔ Answer:

 Check CPU, Memory, and Disk I/O in Cloud Monitoring, review machine type, and resize if necessary.'

'2 Scenario: You need to run a stateless application with auto-scaling. What service do you use?

✔ Answer:

 Use Google Kubernetes Engine (GKE) or Cloud Run.'

'3 Scenario: Your instance group needs to handle high traffic automatically. How do you configure it?

✔ Answer:

 Use Managed Instance Groups (MIGs) with Autoscaler.'

'4 Scenario: Your VM is unreachable via SSH. How do you fix it?

✔ Answer:

 Check firewall rules, metadata SSH keys, and serial console logs.'

'5 Scenario: You need to run a containerized app with minimal configuration. What service should you use?

✔ Answer:

 Use Cloud Run.'

'6 Scenario: Your VM was accidentally deleted. How do you recover it?

✔ Answer:

 Restore from snapshot or backup in Cloud Storage.'

'7 Scenario: Your application needs a global load balancer. What GCP service should you use?

✔ Answer:

 Use Global HTTP(S) Load Balancer.'

'8 Scenario: Your batch processing jobs need to scale dynamically. What service should you use?

✔ Answer:

 Use Google Cloud Dataflow or Batch Jobs with GKE.'

'9 Scenario: You need to deploy a web application without managing servers. What service should you use?

✔ Answer:

 Use App Engine Standard or Cloud Functions.'

'10 Scenario: Your organization wants to reduce VM costs without downtime. What do you do?

✔ Answer:

 Use Committed Use Discounts (CUDs) or Preemptible VMs.'

'# Networking (VPC, Load Balancing, VPN, DNS, Cloud NAT) - 11 to 20

 11 Scenario: Your GCP VM cannot access the internet. What could be the reason?

✔ Answer:

 Check VPC firewall rules, Cloud NAT settings, and external IP assignment.'

'12 Scenario: How do you securely connect an on-prem network to GCP?

✔ Answer:

 Use Cloud VPN or Dedicated Interconnect.'

'13 Scenario: Your web app needs a custom domain. How do you configure it?

✔ Answer:

 Set up Cloud DNS with a CNAME or A record.'

'14 Scenario: Your VM needs a static private IP. How do you configure it?

✔ Answer:

 Assign a reserved private IP in VPC settings.'

'15 Scenario: Your app experiences high latency. How do you improve performance?

✔ Answer:

 Use Cloud CDN and optimize database queries.'

'16 Scenario: How do you expose an internal API securely to external users?

✔ Answer:

 Use Cloud Endpoints or API Gateway.'

'17 Scenario: Your VM should have outbound internet access but no public IP. How do you configure it?

✔ Answer:

 Use Cloud NAT.'

'18 Scenario: Your application requires global load balancing. What should you use?

✔ Answer:

 Use GCP HTTP(S) Global Load Balancer.'

'19 Scenario: Your VMs in different VPCs must communicate securely. What do you configure?

✔ Answer:

 Use VPC Peering.'

'20 Scenario: Your company wants to block certain IP ranges from accessing your app. What do you use?

✔ Answer:

 Configure VPC Firewall Rules or Cloud Armor.'

'# Storage (Cloud Storage, Filestore, Persistent Disks, Backup) - 21 to 30

21 Scenario: Your company needs to store large unstructured data. What service should you use?

✔ Answer:

 Use Cloud Storage.'

'22 Scenario: Your application needs a shared storage solution for multiple VMs. What should you use?

✔ Answer:

 Use Filestore (NFS).'

'23 Scenario: You need to back up on-premise data to GCP. What service do you use?

✔ Answer:

 Use Cloud Storage with Transfer Service.'

'24 Scenario: How do you automatically move infrequently accessed storage to a lower-cost tier?

✔ Answer:

 Configure Object Lifecycle Management.'

'25 Scenario: Your company requires immutable storage for compliance. What feature do you enable?

✔ Answer:

 Enable Bucket Lock with Retention Policy.'

'26 Scenario: Your VM disk is full. How do you extend it?

✔ Answer:

 Resize the Persistent Disk.'

'27 Scenario: You need to migrate large datasets to GCP. What tool do you use?

✔ Answer:

 Use Transfer Appliance.'

'28 Scenario: Your storage needs to be highly durable and globally accessible. What should you use?

✔ Answer:

 Use Multi-Regional Cloud Storage.'

'29 Scenario: Your backup retention needs to be extended. How do you configure it?

✔ Answer:

 Use Cloud Storage Nearline or Archive tiers.'

'30 Scenario: How do you protect data at rest in Cloud Storage?

✔ Answer:

 Use Server-Side Encryption (SSE) and Cloud KMS.'

'# Security & IAM (IAM, Cloud Identity, Security Command Center) - 31 to 40

31 Scenario: Your developers need access to a specific project. How do you grant access?

✔ Answer:

 Assign IAM roles at the project level.'

'32 Scenario: You need to enforce multi-factor authentication for users. What do you configure?

✔ Answer:

 Enable Cloud Identity with MFA.'

'33 Scenario: Your app needs secure access to GCP resources without using service account keys. What do you use?

✔ Answer:

 Use Workload Identity Federation.'

'34 Scenario: How do you protect against DDoS attacks?

✔ Answer:

 Use Cloud Armor.'

'35 Scenario: Your compliance team requires security reports. How do you provide them?

✔ Answer:

 Use Security Command Center and Audit Logs.'

'# Databases (Cloud SQL, BigQuery, Firestore, Spanner) - 41 to 45

41 Scenario: Your app requires a globally distributed NoSQL database. What do you use?

✔ Answer:

 Use Firestore.'

'42 Scenario: Your Cloud SQL instance is slow. How do you optimize performance?

✔ Answer:

 Enable Query Insights and Indexing.'

'43 Scenario: You need high availability for your Cloud SQL database. What do you configure?

✔ Answer:

 Enable Read Replicas and Automatic Failover.'

'44 Scenario: Your database needs to support petabyte-scale analytics. What service should you use?

✔ Answer:

 Use BigQuery.'

'45 Scenario: Your data warehouse needs automated ETL processing. What do you use?

✔ Answer:

 Use Cloud Dataflow.'

'#DevOps & Automation (Cloud Build, Terraform, CI/CD) - 46 to 50

46 Scenario: How do you automate infrastructure deployment in GCP?

✔ Answer:

 Use Terraform or Deployment Manager.'

'47 Scenario: You need to create a CI/CD pipeline for GCP services. What do you use?

✔ Answer:

 Use Cloud Build.'

'48 Scenario: Your GCP pipeline fails. How do you troubleshoot?

✔ Answer:

 Check Cloud Build logs and IAM permissions.'

'49 Scenario: How do you automate VM patching?

✔ Answer:

 Use OS Patch Management.'

'50 Scenario: How do you enforce compliance across GCP projects?

✔ Answer:

 Use Organization Policies and IAM Conditions.'
)


last_index=$(( ${#scenario_gcp[@]} - 1 ))


Total_questions="50"
echo " Total questions:$Total_questions"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_gcp[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear
        echo ' Total 40 questions'
done
clear
echo " End of questions. Thanks for participating"

        ;;


c)

GCP_QUESTIONS=(
    "Which service provides virtual machines in GCP?|a) Google Kubernetes Engine|b) Google Compute Engine|c) Cloud Run|d) Cloud Functions|b"
    "Which GCP service is used for object storage?|a) Cloud Bigtable|b) Cloud Storage|c) Cloud SQL|d) Firebase|b"
    "What is the purpose of Google Cloud IAM?|a) Encrypting cloud data|b) Managing identity and access control|c) Monitoring cloud usage|d) Automating deployments|b"
    "Which GCP service is a fully managed relational database?|a) Cloud SQL|b) Firestore|c) BigQuery|d) Cloud Spanner|a"
    "What does Google Cloud VPC provide?|a) Secure communication between cloud resources|b) Cloud-based development tools|c) CI/CD pipelines|d) Identity management|a"
    "Which service in GCP is used for managing containers?|a) Cloud Run|b) Kubernetes Engine|c) Cloud Functions|d) Cloud Pub/Sub|b"
    "Which service provides a content delivery network (CDN) in GCP?|a) Cloud CDN|b) Cloud Load Balancing|c) Cloud Armor|d) Cloud Spanner|a"
    "What is the purpose of Google Cloud Functions?|a) Running serverless applications|b) Managing SQL databases|c) Storing large datasets|d) Identity access management|a"
    "Which GCP service is best suited for big data analytics?|a) BigQuery|b) Cloud Spanner|c) Cloud SQL|d) Cloud Dataflow|a"
    "What does Google Cloud Monitoring do?|a) Helps secure cloud environments|b) Tracks performance and uptime of services|c) Manages virtual machines|d) Provides AI-powered automation|b"
    "Which service provides automated backups and disaster recovery in GCP?|a) Cloud Storage|b) Cloud Backup|c) Cloud Disaster Recovery|d) Cloud SQL|b"
    "What is the purpose of Google Cloud Security Command Center?|a) Managing user access policies|b) Detecting and responding to security threats|c) Encrypting databases|d) Managing service accounts|b"
    "Which GCP service is used for DevOps and CI/CD pipelines?|a) Cloud Build|b) Cloud Functions|c) Cloud SQL|d) Cloud Run|a"
    "Which GCP service stores secrets like API keys and passwords securely?|a) Cloud IAM|b) Secret Manager|c) Cloud Storage|d) Cloud Functions|b"
    "Which GCP service allows private connectivity between cloud and on-premises networks?|a) Cloud Load Balancer|b) Cloud VPN|c) VPC Peering|d) Cloud Interconnect|d"
    "What is the purpose of Cloud Armor in GCP?|a) Securing cloud storage|b) Protecting applications from DDoS attacks|c) Encrypting API keys|d) Managing VMs|b"
    "Which GCP database service supports NoSQL data models?|a) Cloud SQL|b) BigQuery|c) Firestore|d) Cloud Spanner|c"
    "Which GCP service manages domain name resolution (DNS)?|a) Cloud Router|b) Cloud DNS|c) Cloud Load Balancer|d) Cloud VPN|b"
    "Which tool helps manage cloud infrastructure with automation?|a) Cloud Deployment Manager|b) Cloud Build|c) Kubernetes Engine|d) Cloud Pub/Sub|a"
    "What does Cloud Pub/Sub do?|a) Provides messaging between applications|b) Hosts machine learning models|c) Manages cloud storage|d) Automates network configurations|a"
    "Which GCP service provides a data warehouse solution?|a) Cloud Spanner|b) Cloud SQL|c) BigQuery|d) Firestore|c"
    "Which CLI tool is used to manage GCP resources?|a) gcloud|b) kubectl|c) awscli|d) terraform|a"
    "Which GCP service provides global load balancing?|a) Cloud VPN|b) Cloud Load Balancing|c) Cloud CDN|d) Cloud Functions|b"
    "Which service provides automated failover for databases?|a) Cloud SQL|b) BigQuery|c) Cloud Spanner|d) Firestore|c"
    "Which machine learning service is used to build and train ML models in GCP?|a) AI Platform|b) Cloud Build|c) Cloud Run|d) Cloud Functions|a"
    "Which storage solution allows shared file access in GCP?|a) Cloud Storage|b) Filestore|c) Cloud Spanner|d) Cloud Bigtable|b"
    "Which GCP service helps enforce security policies and compliance across cloud resources?|a) Security Command Center|b) Cloud Armor|c) Cloud Firewall|d) Cloud DNS|a"
    "Which service enables event-driven messaging in GCP?|a) Cloud Pub/Sub|b) Cloud Scheduler|c) Cloud Functions|d) Cloud Build|a"
    "Which service enables secure remote access to GCP resources?|a) Cloud VPN|b) Cloud Interconnect|c) Identity-Aware Proxy|d) Cloud Router|c"
    "Which GCP service provides cost management and billing insights?|a) Cloud Billing|b) BigQuery|c) Cloud AI|d) Cloud Functions|a"
)

SCORE=0
TOTAL_QUESTIONS=${#GCP_QUESTIONS[@]}

clear
echo "================================="
echo "🔥 GCP MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!GCP_QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${GCP_QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Questions: $TOTAL_QUESTIONS"
    echo "Score: $SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering GCP! 🚀"
;;

0) break ;;
*) echo "Invalid option, try again.";;

esac

done
   ;;

 iii)
 while true; do
                                echo " 3 different ways to study this skill"
                                echo " ------------------------------------"
                                echo " a) Interview Questions "
                                echo " b) Scenario based questions "
                                echo " c) Exam(quiz)"
                                echo " 0) Back to the previous menu"       
                                echo " "
                                       read -p "Select your way of study: " azure_way
                                       case $azure_way in


     a)

clear
# Array of questions
azure_questions=(
'# Azure Cloud Interview Questions

1. What is Microsoft Azure?

Answer:

        Microsoft Azure is a cloud computing platform providing services like computing, storage, networking, and databases on a pay-as-you-go basis.'
'2. What are the different types of cloud services in Azure?

Answer:

       The main types are IaaS (Infrastructure as a Service), PaaS (Platform as a Service), and SaaS (Software as a Service).'
'3. What is an Azure Virtual Machine (VM)?

Answer:

      An Azure Virtual Machine is a cloud-based computing instance that provides scalable, on-demand computing resources.'
'4. How do you create a Virtual Machine in Azure?

Answer:

      Go to Azure Portal -> Virtual Machines -> Create VM -> Configure settings and deploy.'
'5. What is Azure Resource Manager (ARM)?

Answer:

      Azure Resource Manager is the management layer that allows users to deploy, manage, and organize resources in Azure.'
'6. What are Azure Availability Zones?

Answer:

      Availability Zones are physically separate data centers within an Azure region that provide redundancy and high availability.'
'7. What is Azure Blob Storage?

Answer:

      Azure Blob Storage is an object storage solution for storing massive amounts of unstructured data such as images, videos, and logs.'
'8. How do you secure data in Azure Storage?

Answer:

      Use encryption at rest, access control, and shared access signatures (SAS).'
'9. What is Azure Virtual Network (VNet)?

Answer:

      Azure VNet allows you to create isolated networks within Azure and securely connect different resources.'
'10. How do you monitor resources in Azure?

Answer:

      Use Azure Monitor, Azure Log Analytics, and Application Insights for tracking performance and diagnosing issues.'
'11. What is Azure Active Directory (AAD)?

Answer:

      Azure Active Directory is a cloud-based identity and access management service for securing applications and users.'
'12. How do you implement Multi-Factor Authentication (MFA) in Azure?

Answer:

      Go to Azure AD -> Security -> MFA -> Enforce MFA for all users.'
'13. What is Azure Kubernetes Service (AKS)?

Answer:

      AKS is a managed Kubernetes service that simplifies container orchestration in Azure.'
'14. What is the purpose of Azure DevOps?

Answer:

      Azure DevOps provides tools for CI/CD, agile development, and project management.'
'15. How do you set up auto-scaling in Azure?

Answer:

      Configure auto-scaling policies using Azure Scale Sets or App Service Auto-Scaling.'
'16. What is Azure Functions?

Answer:

      Azure Functions is a serverless compute service that runs code in response to events.'
'17. What are Azure Logic Apps?

Answer:

      Azure Logic Apps help automate workflows and integrate cloud services with minimal code.'
'18. How do you back up Azure Virtual Machines?

Answer:

      Use Azure Backup to schedule and manage VM backups in Azure Recovery Services Vault.'
'19. What is Azure Site Recovery (ASR)?

Answer:

      ASR is a disaster recovery solution that replicates workloads to Azure to ensure business continuity.'
'20. What is Azure ExpressRoute?

Answer:

      Azure ExpressRoute provides a private, dedicated connection between on-premises networks and Azure.'
'21. How do you configure Azure Firewall?

Answer:

      Deploy an Azure Firewall in a Virtual Network and configure rules to control traffic.'
'22. What is Azure Bastion?

Answer:

      Azure Bastion provides secure and seamless RDP/SSH access to Azure Virtual Machines without exposing public IPs.'
'23. What is the difference between Azure SQL Database and SQL Managed Instance?

Answer:

      Azure SQL Database is a PaaS offering, while SQL Managed Instance is a fully managed SQL Server instance with more compatibility.'
'24. What is Azure Load Balancer?

Answer:

      Azure Load Balancer distributes incoming network traffic across multiple virtual machines to ensure high availability.'
'25. How do you manage costs in Azure?

Answer:

      Use Azure Cost Management + Billing, set budgets, and configure alerts to control spending.'
'26. What is the purpose of Azure Key Vault?

Answer:

      Azure Key Vault is a secure service for managing secrets, encryption keys, and certificates.'
'27. How does Azure Data Factory work?

Answer:

      Azure Data Factory is an ETL service that helps move and transform data across cloud and on-premises environments.'
'28. What are Azure Logic Apps used for?

Answer:

      They enable business process automation by connecting different services using a visual workflow.'
'29. What is Azure API Management?

Answer:

      Azure API Management helps create, secure, and monitor APIs at scale.'
'30. How do you migrate an on-premises database to Azure?

Answer:

      Use Azure Database Migration Service (DMS) to migrate databases with minimal downtime.'
)

last_index=$(( ${#azure_questions[@]} - 1 ))
Total_questions="${#azure_questions[@]}"
echo " Total questions: $Total_questions"

# Loop through the questions one by one
for ((i = 0; i <= $last_index; i++)); do
        echo " "
        echo -n "${azure_questions[$i]}"
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        read -p "Press Enter key to continue..."
        clear

done
clear
echo " End of questions. Thanks for participating!"

;;

b)

clear

scenario_azure=(

'#Compute (Azure VMs, Azure App Services, AKS) - 1 to 10

1 Scenario: Your Azure VM is running slow. How do you troubleshoot performance issues?

✔ Answer:

 Check Azure Monitor, CPU & Memory usage, review VM SKU, and resize if needed.'

'2 Scenario: A web app needs auto-scaling based on traffic load. What Azure service should you use?

✔ Answer:

 Use Azure App Service with Auto-Scaling or Azure Kubernetes Service (AKS).'

'3 Scenario: You need to move an on-premise VM to Azure. What service do you use?

✔ Answer:

 Use Azure Migrate to assess and migrate workloads.'

'4 Scenario: Your Azure VM is inaccessible via RDP/SSH. How do you fix it?

✔ Answer:

 Check NSG rules, ensure VM boot diagnostics are enabled, use Azure Serial Console.'

'5 Scenario: Your app needs to run scheduled background jobs. What service should you use?

✔ Answer:

 Use Azure Functions or Azure Logic Apps.'

'6 Scenario: Your VM was accidentally deleted. How do you recover it?

✔ Answer:

 Restore from Azure Backup Recovery Services Vault.'

'7 Scenario: You need to deploy a web app that supports multiple regions. What should you do?

✔ Answer:

 Deploy to multiple regions using Traffic Manager or Azure Front Door.'

'8 Scenario: You need to run containerized workloads in Azure. What service should you use?

✔ Answer:

 Use Azure Kubernetes Service (AKS) or Azure Container Apps.'

'9 Scenario: Your organization wants to reduce VM costs without deleting them. What options do you have?

✔ Answer:

 Use Azure Reserved Instances, Auto-shutdown, or Spot VMs.'

'10. Scenario: You need to ensure high availability for an Azure VM. How do you configure it?

✔ Answer:

 Deploy VM in an Availability Set or Availability Zone.'

'#Networking (VNet, Load Balancer, VPN, DNS, ExpressRoute) - 11 to 20

11 Scenario: Your VM cannot connect to the internet. What could be the reason?

✔ Answer:

 Check NSG rules, ensure public IP is assigned, and verify UDR (User Defined Route).'

'12 Scenario: How do you connect an on-premise network to Azure securely?

✔ Answer:

 Use Azure VPN Gateway or ExpressRoute.'

'13 Scenario: Your Azure web app must be accessible via a custom domain. What do you configure?

✔ Answer:

 Use Azure DNS and configure a CNAME or A record.'

'14 Scenario: Your Azure VM needs a static private IP. How do you assign it?

✔ Answer:

 Set a static IP in the NIC settings within Azure.'

'15 Scenario: Your web app experiences high latency. How do you improve performance?

✔ Answer:

 Use Azure Front Door or Azure CDN.'

'16 Scenario: You need to securely expose an internal API to external users. What do you use?

✔ Answer:

 Use Azure API Management (APIM) with authentication.'

'17 Scenario: How do you prevent direct internet access to your VMs while still allowing outbound traffic?

✔ Answer:

 Use Azure Firewall or NAT Gateway.'

'18 Scenario: Your application requires global load balancing. What should you use?

✔ Answer:

 Use Azure Traffic Manager or Azure Front Door.'

'19 Scenario: Your VMs in different VNets must communicate securely. What do you configure?

✔ Answer:

 Use VNet Peering.'

'20 Scenario: Your company wants to block specific IP ranges from accessing your Azure web app. What do you use?

✔ Answer:

 Configure NSG rules or use WAF (Web Application Firewall).'

'# Storage (Blob, Files, Disks, Backup, Archive) - 21 to 30
21 Scenario: Your company needs to store large, unstructured data in Azure. What service should you use?

✔ Answer:

 Use Azure Blob Storage.'

'22 Scenario: Your application needs a shared storage solution for multiple VMs. What should you use?

✔ Answer:

 Use Azure Files.'

'23 Scenario: You need to back up on-premise servers to Azure. What service do you use?

✔ Answer:

 Use Azure Backup.'

'24 Scenario: How do you automatically move infrequently accessed storage to a lower-cost tier?

✔ Answer:

 Configure Azure Blob Lifecycle Management.'

'25 Scenario: Your company needs to store immutable logs for compliance. What feature do you enable?

✔ Answer:

 Enable Blob Storage Immutable Policy.'

'26 Scenario: Your Azure VM disk is full. How do you extend it?

✔ Answer:

 Resize the Azure Managed Disk.'

'27 Scenario: You need to migrate terabytes of data to Azure. What tool do you use?

✔ Answer:

 Use Azure Data Box.'

'28 Scenario: Your Azure Files share needs to be accessed from on-premise servers. What do you configure?

✔ Answer:

 Use Azure File Sync.'

'29 Scenario: Your backup retention needs to be extended to 10 years. How do you achieve this?

✔ Answer:

 Configure Azure Backup with Long-Term Retention.'

'30 Scenario: How do you protect data at rest in Azure Storage?

✔ Answer:

 Use Storage Service Encryption (SSE) with Azure Key Vault.'

'# Security & Identity (IAM, Azure AD, Security Center) - 31 to 40

31 Scenario: Your developers need access to a specific resource group. How do you grant access?

✔ Answer:

 Assign RBAC roles at the resource group level.'

'32 Scenario: Your organization needs to enforce multi-factor authentication for all users. What do you do?

✔ Answer:

 Configure Azure AD Conditional Access Policies.'

'33 Scenario: How do you protect Azure resources against DDoS attacks?

✔ Answer:

 Use Azure DDoS Protection.'

'34 Scenario: Your company needs single sign-on (SSO) for SaaS applications. What Azure service do you use?

✔ Answer:

 Use Azure AD SSO.'

'35 Scenario: You need to monitor security compliance across your Azure environment. What do you use?

✔ Answer:

 Use Azure Security Center.'

'# Databases (SQL, Cosmos DB) - 41 to 45

41 Scenario: Your application requires a globally distributed NoSQL database. What do you use?

✔ Answer:

 Use Azure Cosmos DB.'

'42 Scenario: Your Azure SQL database performance is slow. How do you troubleshoot?

✔ Answer:

 Use SQL Performance Insights and enable Auto-Tuning.'

'43 Scenario: You need to set up high availability for Azure SQL. What do you configure?

✔ Answer:

 Enable Geo-Replication.'

'44 Scenario: Your SQL database needs automatic backup. How do you configure it?

✔ Answer:

 Enable Azure SQL Managed Backups.'

'45 Scenario: Your database needs to store JSON-based data. What Azure service do you use?

✔ Answer:

 Use Cosmos DB or SQL JSON Support.'

'# DevOps & Automation (Azure DevOps, CI/CD) - 46 to 50

46 Scenario: How do you automate infrastructure deployment in Azure?

✔ Answer:

 Use ARM Templates or Terraform.'

'47 Scenario: You need to create a CI/CD pipeline for an Azure web app. What do you use?

✔ Answer:

 Use Azure DevOps Pipelines.'

'48 Scenario: Your Azure DevOps build fails. How do you troubleshoot?

✔ Answer:

 Check build logs and pipeline permissions.'

'49 Scenario: How do you automate patching for Azure VMs?

✔ Answer:

 Use Azure Automation Update Management.'

'50 Scenario: How do you enforce compliance for all Azure deployments?

✔ Answer:

 Use Azure Policy.'

)
last_index=$(( ${#scenario_azure[@]} - 1 ))


Total_questions="50"
echo " Total questions:$Total_questions"
echo " Lets practice azure scenario based questions and answers"
echo " Press Enter key"
# Loop through the questions one by one


for ((i =0; i <= $last_index; i++)); do
        echo " "
        echo -n "${scenario_azure[$i]}"
        echo " "
        echo " "
        read -p ""
        clear
        echo " Total 50 questions"
done
clear
echo " Good ! You visited all questions and answers"

        ;;

c)

AZURE_QUESTIONS=(
    "Which service provides virtual machines in Azure?|a) Azure App Service|b) Azure Virtual Machines|c) Azure Functions|d) Azure Kubernetes Service|b"
    "Which Azure storage service is used for unstructured data?|a) Azure Files|b) Azure Blob Storage|c) Azure Queue Storage|d) Azure Table Storage|b"
    "What is Azure Active Directory used for?|a) Network management|b) User authentication and access control|c) Database hosting|d) Web hosting|b"
    "Which Azure service is a fully managed SQL database?|a) Azure SQL Database|b) Azure Cosmos DB|c) Azure Table Storage|d) Azure MySQL|a"
    "What does Azure Virtual Network (VNet) provide?|a) Secure communication between Azure resources|b) Email services|c) Load balancing|d) Data backup|a"
    "Which Azure service provides auto-scaling for web applications?|a) Azure Virtual Machines|b) Azure Kubernetes Service|c) Azure App Service|d) Azure Logic Apps|c"
    "Which service provides a content delivery network (CDN) in Azure?|a) Azure Traffic Manager|b) Azure CDN|c) Azure Front Door|d) Azure ExpressRoute|b"
    "What is Azure Kubernetes Service (AKS) used for?|a) Hosting static websites|b) Running and managing containers|c) Storing files securely|d) Identity and access management|b"
    "Which service is used for serverless computing in Azure?|a) Azure Virtual Machines|b) Azure Kubernetes Service|c) Azure Functions|d) Azure Blob Storage|c"
    "What is the purpose of Azure Monitor?|a) Managing virtual machines|b) Tracking Azure resource performance|c) Encrypting files|d) Handling CI/CD pipelines|b"
    "Which Azure service is used for disaster recovery and backup?|a) Azure Storage|b) Azure Backup|c) Azure Traffic Manager|d) Azure CDN|b"
    "What is Azure Security Center used for?|a) Securely managing user credentials|b) Encrypting files and databases|c) Providing unified security management and threat protection|d) Performing automated backups|c"
    "Which Azure service helps automate deployment pipelines?|a) Azure DevOps|b) Azure Functions|c) Azure Logic Apps|d) Azure AI|a"
    "Which Azure service is used to manage secrets and encryption keys?|a) Azure Active Directory|b) Azure Key Vault|c) Azure Storage|d) Azure Functions|b"
    "Which networking service allows private connectivity between Azure and on-premises networks?|a) Azure Load Balancer|b) Azure VPN Gateway|c) Azure VNet Peering|d) Azure ExpressRoute|d"
    "What is the primary purpose of Azure Firewall?|a) Protecting Azure Virtual Networks from threats|b) Encrypting data at rest|c) Automating application deployments|d) Managing cloud storage|a"
    "Which Azure database service supports NoSQL data models?|a) Azure SQL Database|b) Azure Table Storage|c) Azure Cosmos DB|d) Azure MySQL|c"
    "Which service is used for domain name system (DNS) management in Azure?|a) Azure Traffic Manager|b) Azure DNS|c) Azure Front Door|d) Azure ExpressRoute|b"
    "Which service allows you to automate cloud resource provisioning?|a) Azure DevOps|b) Azure Policy|c) Azure Resource Manager (ARM)|d) Azure Key Vault|c"
    "What is the function of Azure Logic Apps?|a) Automating workflows and processes|b) Managing virtual machines|c) Storing unstructured data|d) Providing AI services|a"
    "Which Azure service provides a data warehouse solution?|a) Azure SQL Database|b) Azure Synapse Analytics|c) Azure Cosmos DB|d) Azure Table Storage|b"
    "Which tool is used for managing Azure resources from the command line?|a) PowerShell|b) Bash|c) Azure CLI|d) Kubernetes|c"
    "Which Azure service is used for implementing load balancing?|a) Azure Traffic Manager|b) Azure Load Balancer|c) Azure Front Door|d) All of the above|d"
    "What is Azure Site Recovery used for?|a) Data backup|b) Disaster recovery|c) Cloud cost management|d) Monitoring application performance|b"
    "Which Azure service allows hosting of machine learning models?|a) Azure Machine Learning|b) Azure AI|c) Azure Cognitive Services|d) Azure DevOps|a"
    "Which storage solution supports file sharing across Azure and on-premises environments?|a) Azure Blob Storage|b) Azure Table Storage|c) Azure Files|d) Azure Queue Storage|c"
    "Which service allows organizations to enforce security policies across Azure subscriptions?|a) Azure Sentinel|b) Azure Security Center|c) Azure Policy|d) Azure Firewall|c"
    "Which Azure service provides a fully managed message queue for application integration?|a) Azure Service Bus|b) Azure Event Hubs|c) Azure Functions|d) Azure Logic Apps|a"
    "Which service enables secure remote access to Azure resources?|a) Azure VPN Gateway|b) Azure ExpressRoute|c) Azure Virtual Network Peering|d) Azure Bastion|d"
    "Which Azure service provides cost management and billing insights?|a) Azure Cost Management + Billing|b) Azure Monitor|c) Azure Advisor|d) Azure Policy|a"
)

SCORE=0
TOTAL_QUESTIONS=${#AZURE_QUESTIONS[@]}

clear
echo "================================="
echo "🔥 Azure MCQ Quiz 🔥"
echo "================================="
echo "Answer the following questions by typing a, b, c, or d"
echo "================================="
echo " "

for i in "${!AZURE_QUESTIONS[@]}"; do
    IFS="|" read -r QUESTION OPTION_A OPTION_B OPTION_C OPTION_D ANSWER <<< "${AZURE_QUESTIONS[$i]}"
    echo "---------------------"
    echo "Current exam status:"
    echo "Total Questions: $TOTAL_QUESTIONS"
    echo "Score: $SCORE"
    echo "---------------------"
    echo "Q$((i+1)). $QUESTION"
    echo "    $OPTION_A"
    echo "    $OPTION_B"
    echo "    $OPTION_C"
    echo "    $OPTION_D"
    echo " "
    echo -n "Your answer: "
    read -r USER_ANSWER
    echo " "

    if [[ "$USER_ANSWER" == "$ANSWER" ]]; then
        echo "✅ Correct!"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
        ((SCORE++))
    else
        echo "❌ Wrong! The correct answer is: $ANSWER"
        echo " "
        read -p "Press ENTER key to move to the next question"
        clear
    fi
done

echo "🎯 Quiz Completed! Your Score: $SCORE / $TOTAL_QUESTIONS"
echo "Keep practicing and mastering Azure! 🚀"
;;

0) break ;;
*) echo "Invalid option. Try again." ;;
 esac
 done 
 ;;
0) break ;;
*) echo "Invalid option. Try again." ;;
esac

done

;;
6)
  clear 
  exit 

;;

    esac


done

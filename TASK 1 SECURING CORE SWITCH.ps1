windows for SOC:
cmd
cd desktop
mkdir QUINCY

task 1 : secure

configure:terminal
username admin privilege 15 secret pass
username quincy privilege 15 secret pass
line vty 0 14
login local
transport input all
end
task2: why companies require vpn for wfh/remote work
implement security on sw

config t
ip domain-name rivanit.com
crypto key generate rsa
ip ssh version 2
end

(enter 1024)


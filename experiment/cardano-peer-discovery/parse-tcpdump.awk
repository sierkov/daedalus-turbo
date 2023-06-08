{
    match($3,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
    ip_src = substr($3,RSTART,RLENGTH)
    sent[ip_src] += $7
    match($5,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
    ip_dst = substr($5,RSTART,RLENGTH)
    rcvd[ip_dst] += $7
}

END {
    for (ip in sent) total[ip] += sent[ip]
    for (ip in rcvd) total[ip] += rcvd[ip]
    n = asorti(total, sorted, "@val_num_desc")
    for (i=1; i <=n; i++) {
        ip = sorted[i]
        if (!ip || substr(ip, 1, 8) == "192.168." || substr(ip, 1, 3) == "10.") continue
        if (substr(ip, 1, 7) == "172.16." || substr(ip, 1, 7) == "172.17." || substr(ip, 1, 7) == "172.18." || substr(ip, 1, 7) == "172.19.") continue
        if (substr(ip, 1, 7) == "172.20." || substr(ip, 1, 7) == "172.21." || substr(ip, 1, 7) == "172.22." || substr(ip, 1, 7) == "172.23.") continue
        if (substr(ip, 1, 7) == "172.24." || substr(ip, 1, 7) == "172.25." || substr(ip, 1, 7) == "172.26." || substr(ip, 1, 7) == "172.27.") continue
        if (substr(ip, 1, 7) == "172.28." || substr(ip, 1, 7) == "172.29." || substr(ip, 1, 7) == "172.30." || substr(ip, 1, 7) == "172.31.") continue
        if (total[ip] > 0) print sorted[i] " sent: " sent[sorted[i]] " rcvd: " rcvd[sorted[i]]
    }
        
}

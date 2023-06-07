{
    match($3,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/);
    ip_src = substr($3,RSTART,RLENGTH);
    if (!seen[ip_src]++) print ip_src
    match($5,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/);
    ip_dst = substr($5,RSTART,RLENGTH);
    if (!seen[ip_dst]++) print ip_dst
}

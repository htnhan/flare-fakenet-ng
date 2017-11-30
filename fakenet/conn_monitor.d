#pragma D option quiet
#pragma D option switchrate=1000hz
#pragma D option destructive
typedef struct sa_endpoints {
    unsigned int            sae_srcif;      /*optional source interface */
    const struct sockaddr   *sae_srcaddr;   /* optional source address */
    socklen_t               sae_srcaddrlen; /* size of source address */
    const struct sockaddr   *sae_dstaddr;    /* destination address */
    socklen_t               sae_dstaddrlen; /* size of destination address */
} sa_endpoints_t;



inline int af_inet = 2;
int ipv4_ident;
string ipv4_addr;


dtrace:::BEGIN
{
    printf("beginning...\n");
}

syscall::connectx:entry
{
    self->connecting = 1;
    self->addr = (struct sa_endpoints *) copyin(arg1, sizeof (struct sa_endpoints));
    self->dst = (struct sockaddr_in *) copyin((user_addr_t )(self->addr->sae_dstaddr), sizeof (struct sockaddr_in));
    self->dport = ntohs(self->dst->sin_port);
    self->execname = execname;
}

syscall::connectx:return
/ self->connecting == 1 && execname == self->execname /
{
    self->connecting = 0;
    self->connected = 1;
    /*
    printf("{");
    printf("\"name\": \"%s\"", execname);
    printf(",");
    printf("\"pktid\": \"%d:%s:%d\"", ipv4_ident, ipv4_addr, self->dport);
    printf(",");
    printf("\"connected\": true");
    printf("}\n");
    */
}

syscall::connect:entry
{
    self->connecting = 1;
    self->dst = (struct sockaddr_in *)copyin(arg1, sizeof(struct sockaddr_in));
    self->dport = ntohs(self->dst->sin_port);
    self->execname = execname;
}

syscall::connect:return
/ self->connecting == 1 && execname == self->execname /
{
    self->connecting = 0;
    self->connected = 1;
}



ip:::send
/ self->connecting == 1 && execname == self->execname/
{
    ipv4_ident = ntohs(args[4]->ipv4_ident);
    ipv4_addr = args[4]->ipv4_daddr;
    printf("{");
    printf("\"name\": \"%s\"", execname);
    printf(",");
    printf("\"pktid\": \"%d:%s:%d\"", ipv4_ident, ipv4_addr, self->dport);
    printf(",");
    printf("\"connecting\": true");
    printf("}\n");
}

syscall::close:return
/ self->connected == 1 && execname == self->execname /
{
    self->connecting = 0;
    printf("{");
    printf("\"name\": \"%s\"", execname);
    printf(",");
    printf("\"pktid\": \"%d:%s:%d\"", ipv4_ident, ipv4_addr, self->dport);
    printf(",");
    printf("\"finish\": true");
    printf("}\n");
}

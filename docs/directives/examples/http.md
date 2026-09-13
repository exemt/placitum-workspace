# capture / archive / preview — http

```nginx
http {
    client_max_body_size 1m;
    waf_body_limit 1m block;
    waf_store driver=redis url=redis://redis:6379 ttl=30s retain_ttl=5m max=8m;
    # внутренний Redis: пакеты и снапшоты активных наборов от keeper
    # (спецификация keeper — `docs/spec.md` его репозитория); обязателен, если есть хоть один active-набор
    waf_sets_store driver=redis url=redis://redis-internal:6379 pool=2 max=512m get_timeout=30s;
    waf_agent_socket /run/waf/verdict.sock;

    # инспекторам: hdr/args, тела нет. cookie — sha256, session выкинут
    waf_capture request headers=64k args=64k;
    waf_capture request headers mask=authorization,cookie;
    waf_capture request args deny=session;

    //тут мы зафиксировали capture, все... это то, что мы заберем на маршруте

    waf_archive request headers args body=128k ttl=30d when=deny;
   
    //мы тут кинем ошибку, при причине того, что архив хочет больше чем capture
    //capture на маршруте становиться фактически тем, что мы вообще получим

    //нам нужна управляющая директива, что будем маскировать, или запрещать...
    waf_archive request headers mask=authorization,cookie deny=session


    waf_preview request headers=30k/1k args=8k/1k;
    waf_preview request headers deny=x-api-key;
    waf_preview request args deny=token;
}
```

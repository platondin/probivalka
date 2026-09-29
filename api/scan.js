export default async function handler(req,res){
  if(req.method!=="POST") return res.status(405).json({error:"POST only"});
  try{
    const {kind,value}=req.body||{};
    if(!kind||!value) return res.status(400).json({error:"kind and value required"});
    const q=String(value).trim();
    const out=[];
    const add=(source,status,data)=>out.push({source,status,data});

    const safeJson=async r=>{try{return await r.json()}catch{return {}}};

    if(kind==="email"){
      const key=process.env.HIBP_API_KEY;
      if(!key){
        add("Have I Been Pwned","needs_api_key","Для автоматической проверки email нужен HIBP_API_KEY на сервере.");
      }else{
        const r=await fetch("https://haveibeenpwned.com/api/v3/breachedaccount/"+encodeURIComponent(q)+"?truncateResponse=true",{
          headers:{"hibp-api-key":key,"user-agent":"probivalka-public-osint"}
        });
        if(r.status===200)add("Have I Been Pwned","ok",await safeJson(r));
        else if(r.status===404)add("Have I Been Pwned","clean",[]);
        else add("Have I Been Pwned","error",{http:r.status});
      }
    }

    if(kind==="username"){
      const headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"};
      if(process.env.GITHUB_TOKEN)headers.Authorization="Bearer "+process.env.GITHUB_TOKEN;
      const r=await fetch("https://api.github.com/search/users?q="+encodeURIComponent(q),{headers});
      if(r.ok){
        const d=await safeJson(r);
        add("GitHub public users","ok",{total_count:d.total_count||0,items:(d.items||[]).slice(0,20).map(u=>({login:u.login,id:u.id,type:u.type,html_url:u.html_url}))});
      }else add("GitHub public users","error",{http:r.status});
    }

    if(kind==="ip"){
      try{
        const token=process.env.IPINFO_TOKEN;
        const r=await fetch("https://ipinfo.io/"+encodeURIComponent(q)+"/json"+(token?"?token="+encodeURIComponent(token):""));
        add("IPinfo",r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
      }catch(e){add("IPinfo","error",{message:e.message})}

      for(const [name,url] of [
        ["ARIN RDAP","https://rdap.arin.net/registry/ip/"+encodeURIComponent(q)],
        ["RIPE RDAP","https://rdap.db.ripe.net/ip/"+encodeURIComponent(q)]
      ]){
        try{
          const r=await fetch(url);
          add(name,r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
        }catch(e){add(name,"error",{message:e.message})}
      }

      add("IKnowWhatYouDownload","not_supported","Официальный автоматический API не подключён. Сайт не открывает сервис и не делает скрытый scraping.");
    }

    if(kind==="domain"){
      try{
        const r=await fetch("https://dns.google/resolve?name="+encodeURIComponent(q)+"&type=A");
        add("Google DNS","ok",await safeJson(r));
      }catch(e){add("Google DNS","error",{message:e.message})}
      try{
        const r=await fetch("https://dns.google/resolve?name="+encodeURIComponent(q)+"&type=MX");
        add("Google DNS MX","ok",await safeJson(r));
      }catch(e){add("Google DNS MX","error",{message:e.message})}
    }

    if(kind==="phone"){
      add("Phone analysis","not_supported","В текущей конфигурации нет подключённого официального API для автоматического поиска по номеру. Никаких переходов на Google или сторонние страницы не выполняется.");
    }

    if(kind==="name"){
      add("Name search","not_supported","Для общего поиска имени нет подключённого официального API. Сайт не подменяет результат ссылкой на Google.");
    }

    if(!out.length)add("Scanner","not_supported","Для этого типа пока нет подключённого автоматического API.");

    return res.status(200).json({kind,value:q,results:out});
  }catch(e){
    return res.status(500).json({error:e.message});
  }
}
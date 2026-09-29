export default async function handler(req,res){
  if(req.method!=="POST") return res.status(405).json({error:"POST only"});
  try{
    const {kind,value,source}=req.body||{};
    if(!kind||!value) return res.status(400).json({error:"kind and value required"});
    const q=String(value).trim();
    if(q.length>500) return res.status(400).json({error:"value too long"});

    const safeJson=async r=>{try{return await r.json()}catch{return {}}};
    const add=(source,status,data)=>({source,status,data});

    async function one(){
      if(kind==="email" && source==="hibp"){
        const key=process.env.HIBP_API_KEY;
        if(!key) return add("Have I Been Pwned","needs_api_key","Для автоматической проверки email нужен HIBP_API_KEY на сервере.");
        const r=await fetch("https://haveibeenpwned.com/api/v3/breachedaccount/"+encodeURIComponent(q)+"?truncateResponse=true",{
          headers:{"hibp-api-key":key,"user-agent":"probivalka-public-osint"}
        });
        if(r.status===200) return add("Have I Been Pwned","ok",await safeJson(r));
        if(r.status===404) return add("Have I Been Pwned","clean",{message:"Email не найден среди известных утечек, проверенных сервисом."});
        return add("Have I Been Pwned","error",{http:r.status});
      }

      if(kind==="username" && source==="github-users"){
        const headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"};
        if(process.env.GITHUB_TOKEN) headers.Authorization="Bearer "+process.env.GITHUB_TOKEN;
        const r=await fetch("https://api.github.com/search/users?q="+encodeURIComponent(q),{headers});
        if(!r.ok) return add("GitHub public users","error",{http:r.status});
        const d=await safeJson(r);
        return add("GitHub public users","ok",{
          total_count:d.total_count||0,
          items:(d.items||[]).slice(0,20).map(u=>({login:u.login,id:u.id,type:u.type,html_url:u.html_url,avatar_url:u.avatar_url}))
        });
      }

      if(kind==="ip"){
        if(source==="ipinfo"){
          try{
            const token=process.env.IPINFO_TOKEN;
            const r=await fetch("https://ipinfo.io/"+encodeURIComponent(q)+"/json"+(token?"?token="+encodeURIComponent(token):""));
            return add("IPinfo",r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
          }catch(e){return add("IPinfo","error",{message:e.message})}
        }
        if(source==="arin-rdap"){
          try{
            const r=await fetch("https://rdap.arin.net/registry/ip/"+encodeURIComponent(q));
            return add("ARIN RDAP",r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
          }catch(e){return add("ARIN RDAP","error",{message:e.message})}
        }
        if(source==="ripe-rdap"){
          try{
            const r=await fetch("https://rdap.db.ripe.net/ip/"+encodeURIComponent(q));
            return add("RIPE RDAP",r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
          }catch(e){return add("RIPE RDAP","error",{message:e.message})}
        }
      }

      if(kind==="domain" && ["dns-a","dns-mx","dns-ns","dns-txt"].includes(source)){
        const typeMap={"dns-a":"A","dns-mx":"MX","dns-ns":"NS","dns-txt":"TXT"};
        try{
          const type=typeMap[source];
          const r=await fetch("https://dns.google/resolve?name="+encodeURIComponent(q)+"&type="+type);
          return add("Google DNS — "+type,r.ok?"ok":"error",r.ok?await safeJson(r):{http:r.status});
        }catch(e){return add("Google DNS — "+type,"error",{message:e.message})}
      }

      if(kind==="phone" && source==="phone-basic"){
        const digits=q.replace(/\D/g,"");
        let normalized=q;
        if(q.trim().startsWith("+")) normalized="+"+digits;
        return add("Phone basic analysis","ok",{
          input:q,
          normalized_digits:digits,
          e164_like:normalized,
          note:"Это локальный технический разбор номера. Для сведений об операторе/владельце требуется отдельный официальный API; приватные данные не извлекаются."
        });
      }

      if(kind==="name" && source==="wikipedia"){
        try{
          const url="https://en.wikipedia.org/w/api.php?action=opensearch&search="+encodeURIComponent(q)+"&limit=10&namespace=0&format=json";
          const r=await fetch(url);
          if(!r.ok)return add("Wikipedia public search","error",{http:r.status});
          const d=await safeJson(r);
          return add("Wikipedia public search","ok",{query:q,titles:d[1]||[],descriptions:d[2]||[],urls:d[3]||[]});
        }catch(e){return add("Wikipedia public search","error",{message:e.message})}
      }

      if(kind==="name" && source==="wikidata"){
        try{
          const url="https://www.wikidata.org/w/api.php?action=wbsearchentities&search="+encodeURIComponent(q)+"&language=en&format=json&limit=10";
          const r=await fetch(url);
          if(!r.ok)return add("Wikidata public search","error",{http:r.status});
          const d=await safeJson(r);
          return add("Wikidata public search","ok",{query:q,items:(d.search||[]).slice(0,10).map(x=>({id:x.id,label:x.label,description:x.description,url:x.concepturi}))});
        }catch(e){return add("Wikidata public search","error",{message:e.message})}
      }

      return add(source||"Scanner","not_supported","Для этого источника в текущей конфигурации нет подключённого автоматического API.");
    }

    const result=await one();
    return res.status(200).json({kind,value:q,results:[result]});
  }catch(e){
    return res.status(500).json({error:e.message});
  }
}
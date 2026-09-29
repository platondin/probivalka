export default async function handler(req,res){
  if(req.method!=="POST") return res.status(405).json({error:"POST only"});
  try{
    const {kind,value}=req.body||{};
    if(!kind||!value) return res.status(400).json({error:"kind and value required"});
    const q=String(value).trim();
    const out=[];
    const add=(source,status,data)=>out.push({source,status,data});

    if(kind==="email"){
      const key=process.env.HIBP_API_KEY;
      if(key){
        const r=await fetch("https://haveibeenpwned.com/api/v3/breachedaccount/"+encodeURIComponent(q)+"?truncateResponse=true",{
          headers:{"hibp-api-key":key,"user-agent":"probivalka-public-osint"}
        });
        if(r.status===200) add("Have I Been Pwned","ok",await r.json());
        else if(r.status===404) add("Have I Been Pwned","clean",[]);
        else add("Have I Been Pwned","error",{http:r.status});
      }else add("Have I Been Pwned","needs_api_key","Добавь HIBP_API_KEY в переменные окружения Vercel.");
    }

    if(kind==="ip"){
      const r=await fetch("https://ipinfo.io/"+encodeURIComponent(q)+"/json"+(process.env.IPINFO_TOKEN?"?token="+encodeURIComponent(process.env.IPINFO_TOKEN):""));
      add("IPinfo",r.ok?"ok":"error",r.ok?await r.json():{http:r.status});
      for(const [name,url] of [
        ["ARIN RDAP","https://rdap.arin.net/registry/ip/"+encodeURIComponent(q)],
        ["RIPE RDAP","https://rdap.db.ripe.net/ip/"+encodeURIComponent(q)]
      ]){
        try{const x=await fetch(url);add(name,x.ok?"ok":"error",x.ok?await x.json():{http:x.status})}catch(e){add(name,"error",{message:e.message})}
      }
    }

    if(kind==="domain"){
      const x=await fetch("https://dns.google/resolve?name="+encodeURIComponent(q)+"&type=ANY");
      add("Google DNS",x.ok?"ok":"error",x.ok?await x.json():{http:x.status});
    }

    // Public-source search results are returned as links rather than scraped,
    // because these services do not expose a documented public API for arbitrary automated collection.
    if(kind==="username"||kind==="name"||kind==="phone"||kind==="email"){
      add("Public web search","links",[
        "https://www.google.com/search?q="+encodeURIComponent('"'+q+'"'),
        "https://www.social-searcher.com/"
      ]);
    }

    return res.status(200).json({kind,value:q,results:out});
  }catch(e){return res.status(500).json({error:e.message})}
}
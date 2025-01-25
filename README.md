```C

                     ________   _______   ________  ___  ___  ___       ________     
                    |\   ___  \|\  ___ \ |\   __  \|\  \|\  \|\  \     |\   __  \    
                    \ \  \\ \  \ \   __/|\ \  \|\ /\ \  \\\  \ \  \    \ \  \|\  \   
                     \ \  \\ \  \ \  \_|/_\ \   __  \ \  \\\  \ \  \    \ \   __  \  
                      \ \  \\ \  \ \  \_|\ \ \  \|\  \ \  \\\  \ \  \____\ \  \ \  \ 
                       \ \__\\ \__\ \_______\ \_______\ \_______\ \_______\ \__\ \__\
                        \|__| \|__|\|_______|\|_______|\|_______|\|_______|\|__|\|__|
                                                                                     
                                 -------a small lib playing with PE's------   

```

Nebulla is a base lib developped to apply various techniques for PE manipulations I discovered during my maldev learning journey.

>[!Important]
>This repos contains samples I wroted. It may not be perfect so don't blame me if you see potentials errors.

## You'll find : 

🟢 **PE loader** : Load PE into memory & execute it.

🟢 **PE mapper** : Manually map PE into memory (local process virtual memory).

🟢 **PE section DUMP** : DUMP PE section to view it.

🟢 **PE add section** : Add a new section to dedicated PE file.

🟢 **PE lib** : Functions to play with PE files (relocations, load imports, map sections & other)

🟢 **PE perms update** : Updating permissions for a dedicated section


## Samples : 

**PE loader**

<img src="https://github.com/Yekuuun/nebula/blob/main/assets/loader.png" alt="DebugInfo" />

**Section DUMP**

<img src="https://github.com/Yekuuun/nebula/blob/main/assets/dump.png" alt="DebugInfo" />

**Add new section**

<img src="https://github.com/Yekuuun/nebula/blob/main/assets/addSection.png" alt="DebugInfo" />

> [!Note]
>Test are made on a simple C x64 bit program displaying a message box using MessageBoxA

---

### Thanks to : 

- <strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
- <strong><a href="https://github.com/hasherezade">Hasherezade</a></strong>

---

> [!Warning]
> This repository was made for learning purpose.

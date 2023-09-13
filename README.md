
# INTRODUCTION TO ACTIVE DIRECTORY

> xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

Para este modulo se van a hacer tareas que haria alguien que administra un active directory primero

```
xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

```
## Estructura

La estructura basica de active directory es

FOREST (que contiene uno o mas) -> dominios (que a su vez pueden tener subdominios) -> Subdominios - > OU Unidades Organizativas ( aqui no entiendo muy bien) -> Objetos (computadores GPO etc)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0b1e7b78-5d54-4628-9b58-9c2cfc09f875)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/11efde5b-7bf4-4194-8c13-afadacf7b5be)

Una analogia buena es que un FOREST es como un pais y un dominio son como sus estados.}

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/270739a3-8025-403e-a392-8e4599c23823)

## Kerberos

La autenticacion de kerberos funciona mas o menos asi:

> As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets.

> 1. When a user initiates a login request to a system, the client they are using to authenticate requests a ticket from the KDC, encrypting the request with the user's password.
> 2.  If the KDC can decrypt the request (AS-REQ) using their password, it will create a Ticket Granting Ticket (TGT) and transmit it to the user. 
> 3. The user then presents its TGT to a Domain Controller to request a Ticket Granting Service (TGS) ticket, encrypted with the associated service's NTLM password hash. 
> 4. Finally, the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash. If the entire process completes appropriately, the user will be permitted to access the requested service or application.

> La autenticación Kerberos desacopla efectivamente las credenciales de los usuarios de sus solicitudes a los recursos consumibles, asegurando que su contraseña no se transmita a través de la red (es decir, accediendo a un sitio interno de intranet de SharePoint). El Centro de distribución de claves Kerberos (KDC) no registra transacciones anteriores. En cambio, el ticket del Servicio de concesión de tickets (TGS) de Kerberos se basa en un Ticket de concesión de tickets (TGT) válido. Se supone que si el usuario tiene un TGT válido, deberá haber acreditado su identidad. El siguiente diagrama explica este proceso en un nivel alto.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/10286f6f-1d91-44e5-b87e-a671a359a9d3)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ee8df339-ab45-49a0-b8c2-3b886e4505b0)


El protocolo Kerberos utiliza el puerto 88 (tanto TCP como UDP). Al enumerar un entorno de Active Directory, a menudo podemos localizar controladores de dominio realizando escaneos de puertos en busca del puerto 88 abierto utilizando una herramienta como Nmap.


## LDAP 

 LDAP utiliza el puerto 389 y LDAP sobre SSL (LDAPS) se comunica a través del puerto 636.

 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/d8063d86-ebdf-4e1c-9320-23cb8306eec6)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/12a35522-7290-4a88-9b35-dd617b360ee4)


## Autenticación NTLM


> Aside from Kerberos and LDAP, Active Directory uses several other authentication methods which can be used (and abused) by applications and services in AD. These include LM, NTLM, NTLMv1, and NTLMv2. LM and NTLM here are the hash names, and NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash. Below is a quick comparison between these hashes and protocols, which shows us that, while not perfect by any means, Kerberos is often the authentication protocol of choice wherever possible. It is essential to understand the difference between the hash types and the protocols that use them.


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/acfe0be0-9a43-467e-a256-38257c9a8217)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/90d64bb4-1857-4881-a331-83e20e272651)

> Es importante tener en cuenta que una cuenta de máquina ( NT AUTHORITY\SYSTEMnivel de acceso) en un entorno AD tendrá la mayoría de los mismos derechos que una cuenta de usuario de dominio estándar. Esto es importante porque no siempre necesitamos obtener un conjunto de credenciales válidas para la cuenta de un usuario individual para comenzar a enumerar y atacar un dominio (como veremos en módulos posteriores). Podemos obtener SYSTEMacceso nivelado a un host de Windows unido a un dominio mediante un exploit de ejecución remota exitosa de código o escalando privilegios en un host. Este acceso a menudo se pasa por alto porque sólo es útil para saquear datos confidenciales (es decir, contraseñas, claves SSH, archivos confidenciales, etc.) en un host en particular. En realidad, el acceso en el contexto de laSYSTEMLa cuenta nos permitirá acceso de lectura a gran parte de los datos dentro del dominio y es un excelente punto de partida para recopilar la mayor cantidad de información posible sobre el dominio antes de continuar con los ataques aplicables relacionados con AD.

## Groups

 Hay dos tipos principales: security y distribution grupos.

 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/171abde6-4903-440e-b4f0-353ff4c016db)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/f70a0968-a5c8-4ad3-97ff-e62ee06fbcd2)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/319ed476-9d83-440f-8875-5cb683e2cecb)




## Snap-in 

> Un "Snap-in" en el contexto de Active Directory (AD) se refiere a una extensión o complemento que se puede agregar a la Consola de Administración de Microsoft Management Console (MMC) para proporcionar funcionalidad adicional relacionada con la administración de Active Directory.
La MMC es una herramienta de administración en Windows que ofrece una interfaz gráfica para administrar diversos componentes del sistema y servicios. Los Snap-ins son módulos que se pueden agregar a la MMC para extender su funcionalidad y permitir a los administradores realizar tareas específicas de administración en AD y otros componentes del sistema.
Por ejemplo, en el caso de Active Directory, hay varios Snap-ins disponibles que se utilizan para administrar distintos aspectos de Active Directory:
Active Directory Users and Computers: Este Snap-in se utiliza para administrar usuarios, grupos, computadoras y otros objetos relacionados con usuarios en Active Directory. Permite la creación, modificación y eliminación de estos objetos.
Active Directory Sites and Services: Se utiliza para administrar la topología de sitios y subredes en Active Directory, lo que es esencial para la replicación eficiente de datos entre controladores de dominio en diferentes ubicaciones físicas.
Active Directory Domains and Trusts: Este Snap-in se utiliza para administrar las relaciones de confianza entre dominios y realizar tareas relacionadas con la gestión de dominios, como establecer la relación de confianza entre dominios.
Group Policy Management: Permite administrar políticas de grupo y objetos de política de grupo en un entorno de Active Directory, lo que es esencial para establecer configuraciones y restricciones en las estaciones de trabajo y servidores en la red.
Active Directory Administrative Center: Proporciona una interfaz de administración moderna y avanzada para administrar objetos de Active Directory, incluyendo la gestión de usuarios y grupos.
En resumen, los Snap-ins en Active Directory son extensiones que se agregan a la MMC para simplificar y facilitar la administración de Active Directory y los componentes relacionados. Estos Snap-ins proporcionan una interfaz gráfica y herramientas específicas para administrar usuarios, grupos, políticas y otros aspectos de la infraestructura de Active Directory en un entorno de Windows.



## Agregar usuarios

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/45fc6349-db06-4ebf-804d-ec5edd7b166f)


Para estas actividades nos recomiendan estas paginas. Dentro vienen todas las acciones que se pueden hacer

> https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

```
New-ADUser -Name "Orion Starchaser" -Accountpassword (ConvertTo-SecureString -AsPlainText (Read-Host "Enter a secure password") -Force ) -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="o.starchaser@inlanefreight.local"}
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3036d794-178d-4561-a192-ec17f63e0bc0)

Via "Active Directory Users and Computers"

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/99235936-546d-4307-9cfb-275935723084)

### Remove users

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/b53cee12-ac16-401a-a576-9035b37ac908)


Para esta accion usa:

```

Remove-ADUser -Identity pvalencia
```

## Unlock a User

```
Unlock-ADAccount -Identity amasters 
```

## Reset User Password (Set-ADAccountPassword)

```
Set-ADAccountPassword -Identity 'amasters' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)
```

## Force Password Change (Set-ADUser)

```
Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

## Groups

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3ed8dc4a-2001-4365-8516-8a298e0a4449)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/a1d1ad4b-2bb7-445d-8e71-65c03b1fabe7)



![image](https://github.com/gecr07/HTB-Academy/assets/63270579/49be07df-9178-40f2-80fc-a2053d45cbb7)


## Create OU

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/48e078f4-41c9-49f2-b8ae-d998109d4ebe)

FIjate como va la ruta de la carpeta mas anidada a la menos ( por asi decirlo)

```

New-ADOrganizationalUnit -Name "Security Analysts" -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=CORP,DC=INLANEFREIGHT,DC=LOCAL"

```


## Create a group

Fijate como va de la carpeta mas anidada a la menos.

```
New-ADGroup -Name "Security Analysts" -SamAccountName analysts -GroupCategory Security -GroupScope Global -DisplayName "Security Analysts" -Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" -Description "Members of this group are Security Analysts under the IT OU"
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/53acbf99-ae33-453f-89a7-141c8f322c90)

```
Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"
```

```
New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```

En Active Directory, el "Logon Name" generalmente se refiere al "SAMAccountName" (Security Account Manager Account Name) de un usuario. El SAMAccountName es un nombre de cuenta único que se utiliza para autenticar a un usuario en un dominio de Windows. Es la parte del nombre de usuario que se utiliza para iniciar sesión en un sistema Windows o en una red basada en Active Directory.

## Members of a group

```
Get-ADGroupMember
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/1bee8505-d3d0-4016-a91b-3e67b46e9c6f)

Para agregar y linkear GPOS lo hicieron con PS no encontre yo otra manera.

## Group policie

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5468ac33-d420-4543-ae23-82470ca68d6a)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ea88d5c0-79c8-41b6-ac6c-09cca8d0ef6d)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/cbd7fbe8-4937-4188-8324-ff24353c19a5)


# Introduction to Active Directory Enumeration & Attacks





























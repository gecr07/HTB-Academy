
# INTRODUCTION TO ACTIVE DIRECTORY

> xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

Para este modulo se van a hacer tareas que haria alguien que administra un active directory primero

```
xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

```

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






























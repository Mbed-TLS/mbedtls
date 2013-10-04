# Microsoft Developer Studio Project File - Name="polarssl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=polarssl - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "polarssl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "polarssl.mak" CFG="polarssl - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "polarssl - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "polarssl - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "polarssl - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir "temp"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir "temp"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "../../include" /D "NDEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "polarssl - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir "temp"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir "temp"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "../../include" /D "_DEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "polarssl - Win32 Release"
# Name "polarssl - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\library\aes.c
# End Source File
# Begin Source File

SOURCE=..\..\library\arc4.c
# End Source File
# Begin Source File

SOURCE=..\..\library\asn1parse.c
# End Source File
# Begin Source File

SOURCE=..\..\library\asn1write.c
# End Source File
# Begin Source File

SOURCE=..\..\library\base64.c
# End Source File
# Begin Source File

SOURCE=..\..\library\bignum.c
# End Source File
# Begin Source File

SOURCE=..\..\library\blowfish.c
# End Source File
# Begin Source File

SOURCE=..\..\library\camellia.c
# End Source File
# Begin Source File

SOURCE=..\..\library\certs.c
# End Source File
# Begin Source File

SOURCE=..\..\library\cipher.c
# End Source File
# Begin Source File

SOURCE=..\..\library\cipher_wrap.c
# End Source File
# Begin Source File

SOURCE=..\..\library\ctr_drbg.c
# End Source File
# Begin Source File

SOURCE=..\..\library\debug.c
# End Source File
# Begin Source File

SOURCE=..\..\library\des.c
# End Source File
# Begin Source File

SOURCE=..\..\library\dhm.c
# End Source File
# Begin Source File

SOURCE=..\..\library\entropy.c
# End Source File
# Begin Source File

SOURCE=..\..\library\entropy_poll.c
# End Source File
# Begin Source File

SOURCE=..\..\library\error.c
# End Source File
# Begin Source File

SOURCE=..\..\library\gcm.c
# End Source File
# Begin Source File

SOURCE=..\..\library\havege.c
# End Source File
# Begin Source File

SOURCE=..\..\library\md.c
# End Source File
# Begin Source File

SOURCE=..\..\library\md_wrap.c
# End Source File
# Begin Source File

SOURCE=..\..\library\md2.c
# End Source File
# Begin Source File

SOURCE=..\..\library\md4.c
# End Source File
# Begin Source File

SOURCE=..\..\library\md5.c
# End Source File
# Begin Source File

SOURCE=..\..\library\net.c
# End Source File
# Begin Source File

SOURCE=..\..\library\padlock.c
# End Source File
# Begin Source File

SOURCE=..\..\library\pbkdf2.c
# End Source File
# Begin Source File

SOURCE=..\..\library\pem.c
# End Source File
# Begin Source File

SOURCE=..\..\library\pkcs11.c
# End Source File
# Begin Source File

SOURCE=..\..\library\pkcs12.c
# End Source File
# Begin Source File

SOURCE=..\..\library\pkcs5.c
# End Source File
# Begin Source File

SOURCE=..\..\library\rsa.c
# End Source File
# Begin Source File

SOURCE=..\..\library\sha1.c
# End Source File
# Begin Source File

SOURCE=..\..\library\sha2.c
# End Source File
# Begin Source File

SOURCE=..\..\library\sha4.c
# End Source File
# Begin Source File

SOURCE=..\..\library\ssl_cache.c
# End Source File
# Begin Source File

SOURCE=..\..\library\ssl_cli.c
# End Source File
# Begin Source File

SOURCE=..\..\library\ssl_srv.c
# End Source File
# Begin Source File

SOURCE=..\..\library\ssl_tls.c
# End Source File
# Begin Source File

SOURCE=..\..\library\timing.c
# End Source File
# Begin Source File

SOURCE=..\..\library\version.c
# End Source File
# Begin Source File

SOURCE=..\..\library\x509parse.c
# End Source File
# Begin Source File

SOURCE=..\..\library\x509write.c
# End Source File
# Begin Source File

SOURCE=..\..\library\xtea.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\polarssl\aes.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\arc4.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\asn1.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\base64.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\bignum.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\blowfish.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\bn_mul.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\camellia.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\certs.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\cipher.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\cipher_wrap.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\ctr_drbg.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\debug.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\des.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\dhm.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\entropy.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\entropy_poll.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\error.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\gcm.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\havege.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\md.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\md_wrap.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\md2.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\md4.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\md5.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\net.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\padlock.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\pbkdf2.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\pem.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\pkcs11.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\pkcs12.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\pkcs5.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\rsa.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\sha1.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\sha2.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\sha4.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\ssl_cache.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\ssl.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\timing.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\version.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\x509.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\x509write.h
# End Source File
# Begin Source File

SOURCE=..\..\include\polarssl\xtea.h
# End Source File
# End Group
# End Target
# End Project

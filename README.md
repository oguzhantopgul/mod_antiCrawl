# mod_antiCrawl
mod_antiCrawl: An anti-crawling module for Apache web servers
An Apache Module That Protects Web Sites From Crawlers

## Introduction

Crawlers  are  beneficial  and  effective  tools  when  they  are  aimed  to  increase  search performance  and  accuracy.  On  the  other  hand,  abuse  of  these  crawling  techniques  is  an issue  that  has  to  be  protected  personally  and  corporately.  mod_antiCrawl  is  an  Apache 
server module which aims to serve crawler protections. 


## Details

mod_antiCrawl has two main anti-crawler functionalities;
  * Detect crawlers by their request densities.
  * Detect crawlers by on the fly hidden trap link injection.


## mod_antiCrawl Installation
The installation of mod_antiCrawl module is done as follows mod_antiCrawl source code is compiled with *apxs* tool. *apxs* is the tool that is used for building and installing Apache extensions.  
{{{
apxs -c mod_anticrawl.c 
}}}
command  compiles  *mod_anticrawl.c*  and  generates  three  files  in  the  same  directory: 
  * mod_anticrawl.la 
  * mod_anticrawl.lo 
  * mod _anticrawl.slo 

{{{
apxs -i mod_anticrawl.la 
}}}

command  installs  module  and  adds  *mod_anticrawl.so*  shared  object  into  apache  modules directory. This directory contains dynamically installed Apache modules. As a next step of installation, *mod_anticrawl.so*  must  be  loaded  in  Apache  configuration  file  *httpd.conf*  (or 
*apache.conf* in Debian based systems). 
 
----

## mod_antiCrawl Configuration
 
In order to use mod_antiCrawl, *mod_anticrawl.so* has to be loaded in configuration file. Loading is done by *LoadModule* directive in configuration file as shown below. 
{{{
LoadModule anticrawl_module /usr/lib/apache2/modules/mod_anticrawl.so 
}}}

*LoadModule* directive  gets  two  attributes.  First  one  is  the  name  of  the  module  that  was declared in the source code and the second is the shared object file with full path. 
  
Module  parameters  can  be  set  in  Apache  configuration  between 
{{{<IfModule></IfModule>}}} tags as follows, 
{{{ 
  <IfModule mod_anticrawl.c> 
      HashTableSize 3097 
      Count 100 
      Interval 3 
      BlockingPeriod 3600 
      AddOutputFilterByType INJECT text/html 
      Inject "s|</a>|</a><a href=dontclick.html style=display:none;>link</a>|ni" 
  </IfModule>  
}}} 
These *HashTableSize* , *Count* ,  *Interval* and *BlockingPeriod* values are configurable parameters  of  the  module.  If  they  are  not  set,  default  values  are  used  by  mod_antiCrawl. Their  default  values  are  set  in  mod_antiCrawl  source  code  as  HashTableSize  is  3097, Count is 100, Interval is 3 and BlockingPeriod is 3600.
 
AddOutputFilterByType  parameter  adds  the  *INJECT*  filter  which  is  used  for injecting hidden trap links.  Inject parameter specifies which expression is replaced with hidden link suffix or prefix. 
{{{ 
Inject "s|</a>|</a><a href=dontclick.html style=display:none;>link</a>|ni" 
}}} 
Expression defines that {{{</a>}}} tag is replaced with     
{{{ 
</a><a href=dontclick.html style=display:none;>link</a> 
}}} 
and these values can be altered in order to inject hidden link into another place.  
 

*These configurations can be combined into the expression that can be stated as follows,*
{{{ 
LoadModule anticrawl_module /usr/lib/apache2/modules/mod_anticrawl.so 
<IfModule mod_anticrawl.c> 
    HashTableSize 3097 
    Count 100 
    Interval 3 
    BlockingPeriod 3600 
    AddOutputFilterByType INJECT text/html 
    Inject "s|</a>|</a><a href=dontclick.html style=display:none;>link</a>|ni" 
</IfModule>
}}}

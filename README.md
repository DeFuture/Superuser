<h4>使用android 手机很多情况下需要root权限，关于root权限获取的原理可以参考以下文章：</h4>
<ul>
<li><a href="http://my.unix-center.net/~Simon_fu/?p=1069" target="_blank">1、云中漫步博客：  Android系统root破解原理分析    </a></li>
<li><a href="http://my.unix-center.net/~Simon_fu/?p=1100" target="_blank">2、云中漫步 ? Android系统root破解原理分析（续）</a></li>
<li><a href="http://blog.csdn.net/tomken_zhang/article/details/6866260" target="_blank">3、zergRush - 随想专栏 - 博客频道 - CSDN.NET </a></li>
<li><a href="http://blog.csdn.net/tomken_zhang/article/details/6870104" target="_blank">4、zergRush (补充) - 随想专栏 - 博客频道 - CSDN.NET </a></li>
<li><a href="http://bbs.pediy.com/showthread.php?t=139738" target="_blank">5、结合init源码剖析android root提权漏洞（CVE-2010-E... </a></li>
<li><a href="http://blog.claudxiao.net/2011/10/zergrush" target="_blank">6、Android提权代码zergRush分析 | i, Claud </a></li>
</ul>

原理是利用了android的两个提权漏洞： CVE-2010-EASY 和 ZergRush。 我把大概原理简单说说：
1， CVE-2010-EASY ： linux的内核的模块化程度很高，很多功能模块是需要到时候再加载，在 android中由init进程来管理这些的。但是这个init进程不会检测发给它的指令的来源，不管是内核发送的，还是用户发送的，它都执行不误，会顺从的去加载或卸载一些模块，而加载的模块都是以root身份运行的。因此你可以给它准备一个精心制作的功能模块(ko文件)，然后触发相应的加载条件，比如热拔插、开关wifi等等， 该功能模块运行后，会生成 /data/local/tmp/rootshell    一个带s位的shell。
2，ZergRush原理： 具有root权限的vold进程使用了libsysutils.so库，该库有个函数存在栈溢出，因此可以root权限执行输入的shellcode。

印象中好像还有个提权漏洞，原理大概是： 某root权限的进程在干完一些事情后会自动降权到普通权限，但是如果普通权限的进程数满了，它就降权不成功，接着它就堂而皇之的以root权限运行了，好像是adbd进程。

扯了半天还没扯到superuser.apk，这个程序是root成功后，专门用来管理root权限使用的，防止被恶意程序滥用。我一直很好奇他是怎么做到这一点的，         

源码地址：
<a href="http://superuser.googlecode.com/svn/trunk" target="_blank"></a>
这个源码有点老，不过感觉原理和最新的superuser应该是差不多的。
带着两个问题我们来分析源码：
1、superuser是怎么知道谁想用root权限？  
2、superuser是如何把用户的选择告诉su程序的那？ 
即superuser和su程序是如何通讯的，他们俩位于不通的时空，一个在java虚拟机中，一个在linux的真实进程中。

共有两个active: SuperuserActivity 和 SuperuserRequestActivity ，呵呵比较简单。
其中SuperuserActivity 主要是用来管理白名单的，就是记住哪个程序已经被允许使用root权限了，省的每次用时都问用户。
SuperuserRequestActivity 就是用来询问用户目前有个程序想使用root权限，是否允许，是否一直允许，即放入白名单。

这个白名单比较关键，是一个sqlite数据库文件，位置：
/data/data/com.koushikdutta.superuser/databases/superuser.sqlite

看完一开始我列的文章，就能明白root的本质就是往 /system/bin/ 下放一个带s位的，不检查调用者权限的su文件。普通程序可以调用该su来运行root权限的命令。superuser.apk中就自带了一个这样的su程序。一开始superuser会检测/system/bin/su是否存在，是否是老子自个放进去的su:


            File su = new File("/system/bin/su");
            // 检测su文件是否存在,如果不存在则直接返回
            if (!su.exists())        
            {
                Toast toast = Toast.makeText(this, "Unable to find /system/bin/su.", Toast.LENGTH_LONG);
                toast.show();
                return;
            }

  //检测su文件的完整性，比较大小，太省事了吧
  //如果大小一样，则认为su文件正确，直接返回了事。
  if (su.length() == suStream.available())  
  {
   suStream.close(); 
   return;   //
  }

           



  // 如果检测到/system/bin/su 文件存在，但是不对头，则把自带的su先写到"/data/data/com.koushikdutta.superuser/su"
    //      再写到/system/bin/su。



                       byte[] bytes = new byte[suStream.available()];
  DataInputStream dis = new DataInputStream(suStream);
  dis.readFully(bytes);
  FileOutputStream suOutStream = new FileOutputStream("/data/data/com.koushikdutta.superuser/su");
  suOutStream.write(bytes);
  suOutStream.close();
  
  Process process = Runtime.getRuntime().exec("su");
  DataOutputStream os = new DataOutputStream(process.getOutputStream());
  os.writeBytes("mount -oremount,rw /dev/block/mtdblock3 /system\n");
  os.writeBytes("busybox cp /data/data/com.koushikdutta.superuser/su /system/bin/su\n");
  os.writeBytes("busybox chown 0:0 /system/bin/su\n");
  os.writeBytes("chmod 4755 /system/bin/su\n");
  os.writeBytes("exit\n");
  os.flush();


上面提到的su肯定是动过手脚的, 我 最纳闷的就是有进程使用root权限，superuser是怎么知道的，看完su 的代码明白了，关键是句：

 sprintf(sysCmd, "am start -a android.intent.action.MAIN 

                                -n com.koushikdutta.superuser/com.koushikdutta.superuser.SuperuserRequestActivity 

                                --ei uid %d --ei pid %d > /dev/null", g_puid, ppid);

 if (system(sysCmd))
  return executionFailure("am.");

原理是am命令，看了下am的用法，明白了：

  usage: am [subcommand] [options]

    start an Activity: am start [-D] [-W] <INTENT>
        -D: enable debugging
        -W: wait for launch to complete

    start a Service: am startservice <INTENT>

    send a broadcast Intent: am broadcast <INTENT>

    start an Instrumentation: am instrument [flags] <COMPONENT>
        -r: print raw results (otherwise decode REPORT_KEY_STREAMRESULT)
        -e <NAME> <VALUE>: set argument <NAME> to <VALUE>
        -p <FILE>: write profiling data to <FILE>
        -w: wait for instrumentation to finish before returning

    start profiling: am profile <PROCESS> start <FILE>
    stop profiling: am profile <PROCESS> stop

    <INTENT> specifications include these flags:
        [-a <ACTION>] [-d <DATA_URI>] [-t <MIME_TYPE>]
        [-c <CATEGORY> [-c <CATEGORY>] ...]
        [-e|--es <EXTRA_KEY> <EXTRA_STRING_VALUE> ...]
        [--esn <EXTRA_KEY> ...]
        [--ez <EXTRA_KEY> <EXTRA_BOOLEAN_VALUE> ...]
        [-e|--ei <EXTRA_KEY> <EXTRA_INT_VALUE> ...]
        [-n <COMPONENT>] [-f <FLAGS>]
        [--grant-read-uri-permission] [--grant-write-uri-permission]
        [--debug-log-resolution]
        [--activity-brought-to-front] [--activity-clear-top]
        [--activity-clear-when-task-reset] [--activity-exclude-from-recents]
        [--activity-launched-from-history] [--activity-multiple-task]
        [--activity-no-animation] [--activity-no-history]
        [--activity-no-user-action] [--activity-previous-is-top]
        [--activity-reorder-to-front] [--activity-reset-task-if-needed]
        [--activity-single-top]
        [--receiver-registered-only] [--receiver-replace-pending]
        [<URI>]


还有个疑点，就是su怎么知道用户是允许root权限还是反对那？ 原来是上面提到的白名单起来作用，superuser把用户的选择放入  ：
/data/data/com.koushikdutta.superuser/databases/superuser.sqlite    数据库中，然后su进程再去读该数据库来判断是否允许。


static int checkWhitelist()
{
sqlite3 *db;
int rc = sqlite3_open_v2(DBPATH, &db, SQLITE_OPEN_READWRITE, NULL);
if (!rc)
{
 char *errorMessage;
 char query[1024];
 sprintf(query, "select * from whitelist where _id=%d limit 1;", g_puid);
 struct whitelistCallInfo callInfo;
 callInfo.count = 0;
 callInfo.db = db;
 rc = sqlite3_exec(db, query, whitelistCallback, &callInfo, &errorMessage);
 if (rc != SQLITE_OK)
 {
  sqlite3_close(db);
  return 0;
 }
 sqlite3_close(db);
 return callInfo.count;
}
sqlite3_close(db);
return 0;
}


至此分析结束，回头看看，原来如此，又想起初中老师的一句话：会者不难，难者不会。    其实原理都不难，只要用心。
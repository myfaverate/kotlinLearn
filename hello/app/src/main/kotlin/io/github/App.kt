package io.github

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import jdk.jfr.MemoryAddress
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.ByteBuffer
import kotlin.time.measureTime

private val logger: KLogger = KotlinLogging.logger {}

/**
 * nohup java -jar /Users/zsh/JarLibs/jadx-1.5.5-all.jar > /dev/null 2>&1 &
 * 最大堆内存使用256m，线程栈大小1m，元空间最大512m
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar zip HelloWorld1 HelloWorld1.zip
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar unzip .\HelloWorld1.zip HelloWorld1
 *
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar gzip HelloWorld1 HelloWorld1.tar.gz
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar unzip HelloWorld1.tar.gz HelloWorld1
 *
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m "--enable-native-access=ALL-UNNAMED" "-Djava.library.path=D:\SoftWare\LanguageProjects\C++Projects\hello_jni\build" -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar brotli HelloWorld1 HelloWorld1.tar.br
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m "--enable-native-access=ALL-UNNAMED" "-Djava.library.path=D:\SoftWare\LanguageProjects\C++Projects\hello_jni\build" -jar D:\SoftWare\LanguageProjects\KotlinProjects\hello\app\build\libs\app.jar unBrotli HelloWorld1.tar.br HelloWorld1
 *
 * mac
 * java -Xmx256m -Xss1m -XX:MaxMetaspaceSize=256m "--enable-native-access=ALL-UNNAMED" "-Djava.library.path=/Users/zsh/Projects/CppProjects/bsdiff/build" -jar /Users/zsh/Projects/KotlinProjects/hello/app/build/libs/app.jar
 */
internal suspend fun main(args: Array<String>): Unit = coroutineScope {
    logger.info { "args: ${args.joinToString()}" }
    CxxUtils.bsDiffCreatePatch("/Users/zsh/Projects/KotlinProjects/hello/hello1.txt", "/Users/zsh/Projects/KotlinProjects/hello/hello2.txt", "/Users/zsh/Projects/KotlinProjects/hello/hello.patch")
    // CxxUtils.bsDiffApplyPatch("/Users/zsh/Projects/KotlinProjects/hello/hello1.txt", "/Users/zsh/Projects/KotlinProjects/hello/hello_new.txt", "/Users/zsh/Projects/KotlinProjects/hello/hello.patch")
    delay(10L)
}

internal suspend fun main1(args: Array<String>): Unit = coroutineScope {
    logger.info { "tmp: ${File.createTempFile("tmp", ".txt")}" }
    if (args.size < 3) {
        logger.info { "usage java -jar zip <srcDir> <dest.zip> or usage java -jar unzip <zipFile> <destDir>" }
        return@coroutineScope
    }
    val duration: kotlin.time.Duration = measureTime {
        when (args[0]) {
            "zip" -> {
                val srcDir = File(args[1])
                val destZip = File(args[2])
                Utils.zipDfs(srcDir, destZip)
            }

            "unzip" -> {
                val zipFile = File(args[1])
                val destDir = File(args[2])
                Utils.unzip(zipFile, destDir)
            }

            "gzip" -> {
                val srcDir = File(args[1])
                val destGzip = File(args[2])
                Utils.tarGzDfs(srcDir, destGzip)
            }

            "ungzip" -> {
                val gzipFile = File(args[1])
                val destDir = File(args[2])
                Utils.unTarGz(gzipFile, destDir)
            }

            "brotli" -> {
                val srcDir = File(args[1])
                val destBr = File(args[2])
                Utils.tarBrDfs(srcDir, destBr)
            }

            "unBrotli" -> {
                val tarBrFile = File(args[1])
                val destDir = File(args[2])
                Utils.unTarBr(tarBrFile, destDir)
            }

            else -> {
                logger.info {
                    """
                        usage java -jar method <srcDir> <destFile> or usage java -jar method <destFile> <destDir>
                        method: 
                            1. zip or unzip
                            2. gzip or ungzip
                            3. unBrotli
                    """.trimIndent()
                }
            }
        }
    }
    logger.info { "耗时: $duration" }
}
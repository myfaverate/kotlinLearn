package io.github

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarFile
import org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.io.path.inputStream

// https://www.baeldung.com/kotlin/kotlin-logging-library
private val logger: KLogger = KotlinLogging.logger {}


internal object Utils {
    /**
     * 防止 Zip Slip 漏洞
     * zipFile: 待解压的zip文件
     * targetDir: 解压后的目标目录
     */
    internal fun unzip(zipFile: File, targetDir: File){
        // 目录不存在则创建
        logger.info { "targetDir: ${targetDir.absolutePath}" }
        if (!targetDir.exists()){
            val isSuccess: Boolean = targetDir.mkdirs()
            if (!isSuccess){
                throw RuntimeException("创建目标目录失败: ${targetDir.absolutePath}")
            }
        }
        if (!targetDir.isDirectory) {
            throw RuntimeException("targetDir必须是一个目录")
        }
        // 获取目标目录的标准绝对路径，末尾加上分隔符以确保匹配完整目录名
        val canonicalTargetDirPath = "${targetDir.canonicalPath.replace(File.separatorChar, '/')}/"
        logger.info { "canonicalTargetDirPath: $canonicalTargetDirPath" }
        ZipFile(zipFile).use { zipFile: ZipFile ->
            zipFile.entries().asSequence()
                .forEach { entry: ZipEntry ->
                    val entryFile = File(targetDir, entry.name)
                    // --- 安全检查核心代码 ---
                    val canonicalEntryPath: String = entryFile.canonicalPath.replace(File.separatorChar, '/')
                    logger.info { "canonicalEntryPath: $canonicalEntryPath, entry.isDirectory: ${entry.isDirectory}" }
                    if (!canonicalEntryPath.startsWith(canonicalTargetDirPath)) {
                        throw SecurityException("检测到 Zip Slip 攻击！恶意条目路径: ${entry.name}")
                    }
                    if (entry.isDirectory){
                        val isSuccess: Boolean = entryFile.mkdirs()
                        logger.info { "解压的是一个目录, 创建目录是否成功: $isSuccess" }
                    } else {
                        val parentFile: File? = entryFile.parentFile
                        if (parentFile?.exists() == false){
                            val isSuccess: Boolean = parentFile.mkdirs()
                            logger.info { "压缩文件父目录是否创建成功: $isSuccess" }
                        }
                        zipFile.getInputStream(entry).buffered().use { bufferedInputStream: BufferedInputStream ->
                            entryFile.outputStream().buffered().use { bufferedOutputStream ->
                                bufferedInputStream.copyTo(out = bufferedOutputStream)
                            }
                        }
                    }
                }
        }
    }
    /**
     * 访问者模式
     * srcDir: 待压缩的目录
     * zipFile: 生成的zip文件，生成在srcDir的父目录下，命名为srcDir.zip
     */
    internal fun zipDfs(srcDir: File, zipFile: File){
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }
        val srcPath: Path = srcDir.toPath()
        ZipOutputStream(zipFile.outputStream().buffered()).use { zipOutputStream: ZipOutputStream ->
            Files.walkFileTree(srcPath, object : SimpleFileVisitor<Path>(){
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    // 1. 处理目录 Entry（记得加 "/"）
                    val relativePath: String = srcPath.relativize(dir).toString().replace(File.separatorChar, '/')
                    logger.info { "preVisitDirectory relativePath: $relativePath" }
                    if (relativePath.isNotEmpty()) {
                        zipOutputStream.putNextEntry(ZipEntry("$relativePath/"))
                        zipOutputStream.closeEntry()
                    }
                    return FileVisitResult.CONTINUE
                }

                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    // 2. 处理文件内容
                    val relativePath: String = srcPath.relativize(file).toString().replace(File.separatorChar, '/')
                    logger.info { "visitFile relativePath: $relativePath" }
                    zipOutputStream.putNextEntry(ZipEntry(relativePath))
                    Files.copy(file, zipOutputStream) // 使用 NIO 的直接拷贝，效率更高
                    zipOutputStream.closeEntry()
                    return FileVisitResult.CONTINUE
                }
            })
        }
    }
    /**
     * bfs适合处理目录层级较深的情况，dfs适合处理目录层级较浅但文件数量较多的情况, 链接文件不考虑
     * srcDir: 待压缩的目录
     * zipFile: 生成的zip文件，生成在srcDir的父目录下，命名为srcDir.zip
     */
    internal fun zipBfs(srcDir: File, zipFile: File) {
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }
        val dirs = ArrayDeque<File>(initialCapacity = 256)
        val bytes = ByteArray(size = 1024 * 8)
        dirs.add(srcDir)
        ZipOutputStream(zipFile.outputStream().buffered()).use { zipOutputStream: ZipOutputStream ->
            while (dirs.isNotEmpty()) {
                val node: File = dirs.removeFirst()
                node.listFiles()?.forEach { file: File ->
                    if (file.isDirectory) {
                        dirs.add(file)
                        val zipEntry = ZipEntry("${file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')}/") // 命名参数
                        logger.info { "zip -> isDirectory zipEntryName: ${zipEntry.name}" }
                        zipOutputStream.putNextEntry(zipEntry)
                        zipOutputStream.closeEntry()
                    } else {
                        val relativePath: String = file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')
                        logger.info { "zip -> isFile relativePath: $relativePath" }
                        val zipEntry = ZipEntry(relativePath)
                        zipOutputStream.putNextEntry(zipEntry)
                        file.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                            var length: Int
                            while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                                zipOutputStream.write(bytes, 0, length)
                            }
                        }
                        zipOutputStream.closeEntry()
                    }
                }
            }
        }
    }

    /**
     * 需要额外依赖 commons-compress 库
     * srcDir: 待压缩的目录
     * tarGzFile: 生成的tar.gz文件，生成在srcDir的父目录下，命名为srcDir.tar.gz
     */
    internal fun tarGzBfs(srcDir: File, tarGzFile: File){
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }
        val dirs = ArrayDeque<File>(initialCapacity = 256)
        val bytes = ByteArray(size = 1024 * 8)
        dirs.add(srcDir)
        val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
        logger.info { "tempTarFile: $tempTarFile" }
        TarArchiveOutputStream(tempTarFile.outputStream().buffered()).use { tarArchiveOutputStream: TarArchiveOutputStream ->
            tarArchiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            while (dirs.isNotEmpty()) {
                val node: File = dirs.removeFirst()
                node.listFiles()?.forEach { file: File ->
                    if (file.isDirectory) {
                        dirs.add(file)
                        val tarEntry = TarArchiveEntry(file, "${file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')}/")
                        logger.info { "tar -> isDirectory tarEntryName: ${tarEntry.name}, file: $file" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        tarArchiveOutputStream.closeArchiveEntry()
                    } else {
                        val relativePath: String = file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')
                        val tarEntry = TarArchiveEntry(file, relativePath)
                        logger.info { "tar -> isFile relativePath: $relativePath, tarEntryName: ${tarEntry.name}, file: $file" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        file.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                            var length: Int
                            while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                                tarArchiveOutputStream.write(bytes, 0, length)
                            }
                        }
                        tarArchiveOutputStream.closeArchiveEntry()
                    }
                }
            }
        }
        GzipCompressorOutputStream(tarGzFile.outputStream().buffered()).use { gzipOutputStream: GzipCompressorOutputStream ->
            tempTarFile.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                var length: Int
                while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                    gzipOutputStream.write(bytes, 0, length)
                }
            }
        }
        // 删除临时tar文件
        val isDeleted: Boolean = tempTarFile.delete()
        logger.info { "删除临时tar文件是否成功: $isDeleted" }
    }

    /**
     * 压缩为tar.gz文件，tar.gz文件是先将目录打包成tar文件，再使用gzip算法压缩tar文件生成的，压缩时需要先将目录打包成tar文件，再使用gzip算法压缩tar文件生成tar.gz文件
     * srcDir: 待压缩的目录
     * tarGzFile: 生成的tar.gz文件，生成在srcDir的父目录下，命名为srcDir.tar.gz
     */
    internal fun tarGzDfs(srcDir: File, tarGzFile: File){
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }

        val srcPath: Path = srcDir.toPath()
        val bytes = ByteArray(size = 1024 * 8)

        val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
        logger.info { "tempTarFile: $tempTarFile" }

        TarArchiveOutputStream(tempTarFile.outputStream().buffered()).use { tarArchiveOutputStream: TarArchiveOutputStream ->
            tarArchiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            Files.walkFileTree(srcPath, object : SimpleFileVisitor<Path>(){
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    // tar.gz格式没有目录Entry，目录信息包含在文件Entry的路径中
                    val relativePath: String = srcPath.relativize(dir).toString().replace(File.separatorChar, '/')
                    logger.info { "preVisitDirectory relativePath: [$relativePath]" }
                    if (relativePath.isNotEmpty()){
                        val tarEntry = TarArchiveEntry(dir.toFile(), "$relativePath/")
                        logger.info { "preVisitDirectory tarEntryName: ${tarEntry.name}, file: ${dir.toFile()}" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        tarArchiveOutputStream.closeArchiveEntry()
                    }
                    return FileVisitResult.CONTINUE
                }

                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    val relativePath: String = srcPath.relativize(file).toString().replace(File.separatorChar, '/')
                    val tarEntry = TarArchiveEntry(file.toFile(), relativePath)
                    logger.info { "visitFile relativePath: $relativePath, file: $file, tarEntry: ${tarEntry.name}" }
                    tarArchiveOutputStream.putArchiveEntry(tarEntry)
                    file.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                        var length: Int
                        while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                            tarArchiveOutputStream.write(bytes, 0, length)
                        }
                    }
                    tarArchiveOutputStream.closeArchiveEntry()
                    return FileVisitResult.CONTINUE
                }
            })
        }
        GzipCompressorOutputStream(tarGzFile.outputStream().buffered()).use { gzipOutputStream: GzipCompressorOutputStream ->
            tempTarFile.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                var length: Int
                while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                    gzipOutputStream.write(bytes, 0, length)
                }
            }
        }
        // 删除临时tar文件
        val isDeleted: Boolean = tempTarFile.delete()
        logger.info { "删除临时tar文件是否成功: $isDeleted" }
    }

    /**
     * 解压tar.gz文件，tar.gz文件是先将目录打包成tar文件，再使用gzip算法压缩tar文件生成的，解压时需要先使用gzip算法解压成tar文件，再解压tar文件
     * tarGzFile: 待解压的tar.gz文件
     * targetDir: 解压后的目标目录
     */
    internal fun unTarGz(tarGzFile: File, targetDir: File){
        // 目录不存在则创建
        logger.info { "targetDir: ${targetDir.absolutePath}" }
        if (!targetDir.exists()){
            val isSuccess: Boolean = targetDir.mkdirs()
            if (!isSuccess){
                throw RuntimeException("创建目标目录失败: ${targetDir.absolutePath}")
            }
        }
        if (!targetDir.isDirectory) {
            throw RuntimeException("targetDir必须是一个目录")
        }
        GzipCompressorInputStream(tarGzFile.inputStream().buffered()).use { gzipCompressorInputStream: GzipCompressorInputStream ->
            val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
            tempTarFile.outputStream().buffered().use { bufferedOutputStream: BufferedOutputStream ->
                gzipCompressorInputStream.copyTo(out = bufferedOutputStream)
            }
            logger.info { "tempTarFile: $tempTarFile, size: ${tempTarFile.length()}" }
            TarFile(tempTarFile).use { tarFile: TarFile ->
                tarFile.entries.asSequence()
                    .forEach { entry: TarArchiveEntry ->
                        val entryFile = File(targetDir, entry.name)
                        logger.info { "entry.name: ${entry.name}, entry.isDirectory: ${entry.isDirectory}" }
                        if (entry.isDirectory) {
                            val isSuccess: Boolean = entryFile.mkdirs()
                            logger.info { "解压的是一个目录, 创建目录是否成功: $isSuccess" }
                        } else {
                            val parentFile: File? = entryFile.parentFile
                            if (parentFile?.exists() == false){
                                val isSuccess: Boolean = parentFile.mkdirs()
                                logger.info { "压缩文件父目录是否创建成功: $isSuccess" }
                            }
                            tarFile.getInputStream(entry).buffered().use { bufferedInputStream: BufferedInputStream ->
                                entryFile.outputStream().buffered().use { bufferedOutputStream ->
                                    bufferedInputStream.copyTo(out = bufferedOutputStream)
                                }
                            }
                        }
                    }
            }
            // 删除临时tar文件
            val isDeleted: Boolean = tempTarFile.delete()
            logger.info { "删除临时tar文件是否成功: $isDeleted" }
        }
    }

    /**
     * 解压tar.br文件，tar.br文件是先将目录打包成tar文件，再使用brotli算法压缩tar文件生成的，解压时需要先使用brotli算法解压成tar文件，再解压tar文件
      * tarBrFile: 待解压的tar.br文件
      * targetDir: 解压后的目标目录
     */
    internal fun unTarBr(tarBrFile: File, targetDir: File){
        // 目录不存在则创建
        logger.info { "targetDir: ${targetDir.absolutePath}" }
        if (!targetDir.exists()){
            val isSuccess: Boolean = targetDir.mkdirs()
            if (!isSuccess){
                throw RuntimeException("创建目标目录失败: ${targetDir.absolutePath}")
            }
        }
        if (!targetDir.isDirectory) {
            throw RuntimeException("targetDir必须是一个目录")
        }
        BrotliCompressorInputStream(tarBrFile.inputStream().buffered()).use { brotliCompressorInputStream: BrotliCompressorInputStream ->
            val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
            tempTarFile.outputStream().buffered().use { bufferedOutputStream: BufferedOutputStream ->
                brotliCompressorInputStream.copyTo(out = bufferedOutputStream)
            }
            logger.info { "tempTarFile: $tempTarFile, size: ${tempTarFile.length()}" }
            TarFile(tempTarFile).use { tarFile: TarFile ->
                tarFile.entries.asSequence()
                    .forEach { entry: TarArchiveEntry ->
                        val entryFile = File(targetDir, entry.name)
                        logger.info { "entry.name: ${entry.name}, entry.isDirectory: ${entry.isDirectory}" }
                        if (entry.isDirectory) {
                            val isSuccess: Boolean = entryFile.mkdirs()
                            logger.info { "解压的是一个目录, 创建目录是否成功: $isSuccess" }
                        } else {
                            val parentFile: File? = entryFile.parentFile
                            if (parentFile?.exists() == false){
                                val isSuccess: Boolean = parentFile.mkdirs()
                                logger.info { "压缩文件父目录是否创建成功: $isSuccess" }
                            }
                            tarFile.getInputStream(entry).buffered().use { bufferedInputStream: BufferedInputStream ->
                                entryFile.outputStream().buffered().use { bufferedOutputStream ->
                                    bufferedInputStream.copyTo(out = bufferedOutputStream)
                                }
                            }
                        }
                    }
            }
            // 删除临时tar文件
            val isDeleted: Boolean = tempTarFile.delete()
            logger.info { "删除临时tar文件是否成功: $isDeleted" }
        }
    }

    /**
     * 文件排列顺序会影响压缩文件大小，一般来说，目录层级较深的文件放在前面会比目录层级较浅的文件放在前面压缩后的文件更小，因为目录层级较深的文件路径更长，压缩算法可以利用路径的相似性来更有效地压缩数据
     * 需要额外依赖 commons-compress 库
     * srcDir: 待压缩的目录
     * tarGzFile: 生成的tar.gz文件，生成在srcDir的父目录下，命名为srcDir.tar.gz
     */
    internal fun tarBrBfs(srcDir: File, tarBrFile: File){
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }
        val dirs = ArrayDeque<File>(initialCapacity = 256)
        val bytes = ByteArray(size = 1024 * 8)
        dirs.add(srcDir)
        val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
        logger.info { "tempTarFile: $tempTarFile" }
        TarArchiveOutputStream(tempTarFile.outputStream().buffered()).use { tarArchiveOutputStream: TarArchiveOutputStream ->
            tarArchiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            while (dirs.isNotEmpty()) {
                val node: File = dirs.removeFirst()
                node.listFiles()?.forEach { file: File ->
                    if (file.isDirectory) {
                        dirs.add(file)
                        val tarEntry = TarArchiveEntry(file, "${file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')}/")
                        logger.info { "tar -> isDirectory tarEntryName: ${tarEntry.name}, file: $file" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        tarArchiveOutputStream.closeArchiveEntry()
                    } else {
                        val relativePath: String = file.toRelativeString(base = srcDir).replace(File.separatorChar, '/')
                        val tarEntry = TarArchiveEntry(file, relativePath)
                        logger.info { "tar -> isFile relativePath: $relativePath, tarEntryName: ${tarEntry.name}, file: $file" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        file.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                            var length: Int
                            while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                                tarArchiveOutputStream.write(bytes, 0, length)
                            }
                        }
                        tarArchiveOutputStream.closeArchiveEntry()
                    }
                }
            }
        }
        BrotliOutputStream(tarBrFile.outputStream().buffered()).use { brotliOutputStream: BrotliOutputStream ->
            tempTarFile.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                var length: Int
                while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                    brotliOutputStream.write(bytes, 0, length)
                }
            }
        }
        // 删除临时tar文件
        val isDeleted: Boolean = tempTarFile.delete()
        logger.info { "删除临时tar文件是否成功: $isDeleted" }
    }

    /**
     * 压缩为tar.gz文件，tar.gz文件是先将目录打包成tar文件，再使用gzip算法压缩tar文件生成的，压缩时需要先将目录打包成tar文件，再使用gzip算法压缩tar文件生成tar.gz文件
     * srcDir: 待压缩的目录
     * tarGzFile: 生成的tar.gz文件，生成在srcDir的父目录下，命名为srcDir.tar.gz
     */
    internal fun tarBrDfs(srcDir: File, tarBrFile: File){
        if (!srcDir.isDirectory) {
            throw RuntimeException("源路径必须是一个目录: ${srcDir.absolutePath}")
        }

        val srcPath: Path = srcDir.toPath()
        val bytes = ByteArray(size = 1024 * 8)

        val tempTarFile: File = File.createTempFile(/* prefix */"tempTar", /* suffix */".tar")
        logger.info { "tempTarFile: $tempTarFile" }

        TarArchiveOutputStream(tempTarFile.outputStream().buffered()).use { tarArchiveOutputStream: TarArchiveOutputStream ->
            tarArchiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            Files.walkFileTree(srcPath, object : SimpleFileVisitor<Path>(){
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    // tar.gz格式没有目录Entry，目录信息包含在文件Entry的路径中
                    val relativePath: String = srcPath.relativize(dir).toString().replace(File.separatorChar, '/')
                    logger.info { "preVisitDirectory relativePath: [$relativePath]" }
                    if (relativePath.isNotEmpty()){
                        val tarEntry = TarArchiveEntry(dir.toFile(), "$relativePath/")
                        logger.info { "preVisitDirectory tarEntryName: ${tarEntry.name}, file: ${dir.toFile()}" }
                        tarArchiveOutputStream.putArchiveEntry(tarEntry)
                        tarArchiveOutputStream.closeArchiveEntry()
                    }
                    return FileVisitResult.CONTINUE
                }

                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    val relativePath: String = srcPath.relativize(file).toString().replace(File.separatorChar, '/')
                    val tarEntry = TarArchiveEntry(file.toFile(), relativePath)
                    logger.info { "visitFile relativePath: $relativePath, file: $file, tarEntry: ${tarEntry.name}" }
                    tarArchiveOutputStream.putArchiveEntry(tarEntry)
                    file.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                        var length: Int
                        while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                            tarArchiveOutputStream.write(bytes, 0, length)
                        }
                    }
                    tarArchiveOutputStream.closeArchiveEntry()
                    return FileVisitResult.CONTINUE
                }
            })
        }
        BrotliOutputStream(tarBrFile.outputStream().buffered()).use { brotliOutputStream: BrotliOutputStream ->
            tempTarFile.inputStream().buffered().use { bufferedInputStream: BufferedInputStream ->
                var length: Int
                while (bufferedInputStream.read(bytes).also { length = it } > 0) {
                    brotliOutputStream.write(bytes, 0, length)
                }
            }
        }
        // 删除临时tar文件
        val isDeleted: Boolean = tempTarFile.delete()
        logger.info { "删除临时tar文件是否成功: $isDeleted" }
    }
}
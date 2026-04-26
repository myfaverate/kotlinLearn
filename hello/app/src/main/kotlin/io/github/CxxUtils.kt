package io.github

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.file.Path

private val logger: KLogger = KotlinLogging.logger {}

internal object CxxUtils {
    private val CREATE_PATCH: MethodHandle
    private val APPLY_PATCH: MethodHandle
    init {

        // 1. 先用传统的系统方法加载，它会识别 -Djava.library.path
        System.loadLibrary("bsdiff")
        // 2. 使用 loaderLookup，它能找到上面加载的库里的函数
        val symbolLookup: SymbolLookup = SymbolLookup.loaderLookup()

        val desc: FunctionDescriptor = FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
        val linker: Linker = Linker.nativeLinker()
        CREATE_PATCH = linker.downcallHandle(symbolLookup.find("bsdiff_create_patch")?.orElseThrow(), desc)
        APPLY_PATCH = linker.downcallHandle(symbolLookup.find("bsdiff_apply_patch")?.orElseThrow(), desc)
    }
    internal fun bsDiffCreatePatch(oldPath: String, newPath: String, patchPath: String){
        Arena.ofConfined().use { arena: Arena ->
            val result: Int = CREATE_PATCH.invoke(
                arena.allocateFrom(oldPath),
                arena.allocateFrom(newPath),
                arena.allocateFrom(patchPath),
            ) as Int
            logger.info { "bsDiffCreatePatch result: $result" }
            if (result != 0){
                throw RuntimeException("bsdiff_create_patch error")
            }
        }
    }
    internal fun bsDiffApplyPatch(oldPath: String, newPath: String, patchPath: String){
        Arena.ofConfined().use { arena: Arena ->
            val result: Int = APPLY_PATCH.invoke(
                arena.allocateFrom(oldPath),
                arena.allocateFrom(newPath),
                arena.allocateFrom(patchPath),
            ) as Int
            logger.info { "bsDiffApplyPatch result: $result" }
            if (result != 0){
                throw RuntimeException("bsdiff_create_patch error")
            }
        }
    }
}
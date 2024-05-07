
var malloc = new NativeFunction(Module.findExportByName('libc.so', 'malloc'), 'pointer', ['int'])

function activity_thread_getApplication() {
    var ActivityThread = Java.use("android.app.ActivityThread")
    // console.log(ActivityThread)
    var activity_thread = ActivityThread.currentActivityThread()
    // console.log(activity_thread)
    var application = activity_thread.getApplication()
    // console.log(application)
    return application

}


function file_exsit(file) {
    var f
    try {
        f = new File(file, 'rb')
    } catch (error) {

    }
    if (f) {
        return true
    } else {
        return false
    }
}

function copy_file(source_file, dest_path, name) {

    var data = File.readAllBytes(source_file)
    var dest = dest_path + '/' + name
    File.writeAllBytes(dest, data)
    console.log('copy_file success')
    return dest

}


// 找so，如果是我自己的还会load一下
function load_my_so(context) {
    var so = 'libdutil.so'
    console.log('load_my_so enter', so)
    var base = Process.findModuleByName(so)
    var path = context.getCacheDir().getPath()
    console.log('getCacheDir',path)
    var so = path + '/libdutil.so'
    if (!base) {
        if (file_exsit(so)) {
            // console.log(file_exsit(so))
            base = Module.load(so)
        } else {

            copy_file('/sdcard/giao/libdutil.so', path, 'libdutil.so')
            base = Module.load(so)
        }

    }
    var base_addr = base.base
    console.log(base.name, base_addr, base.size, base.path)
    console.log('')
    return base

}


function build_re(str) {
    var re_str = `\.*${str}.*`
    return new RegExp(re_str, 'i');
}

class BinSupport {
    // 全部以字符串来操作

    // 填充到足够位数，正数补0，负数补1
    static binFillTobinWidth(binStr, binWidth = 64) {


        var length = binStr.length
        if (binStr[0] == 0) {
            // 正数补0
            for (let i = 0; i < binWidth - length; i++) {
                binStr = '0' + binStr
            }
        } else {
            // 负数补1
            for (let i = 0; i < binWidth - length; i++) {
                binStr = '1' + binStr
            }
        }

        return binStr
    }

    // 二进制加法,参数位数不一样会进行算术填充，返回结果和溢出位,数组
    static binAdd(v1, v2) {
        var length = ''
        if (v1.length < v2.length) {
            length = v2.length
            v1 = this.binFillTobinWidth(v1, length)
        }

        // console.log(v1,v2)
        var ch = 0
        var res = ''
        for (let i = 0; i < v1.length; i++) {
            var num1 = parseInt(v1[v1.length - 1 - i], 10)
            var num2 = parseInt(v2[v1.length - 1 - i], 10)

            var tempRes = ch + num1 + num2
            if (tempRes > 1) {
                ch = 1
                tempRes = tempRes - 2
            } else {
                ch = 0
            }
            res = tempRes.toString(2) + res
        }
        var resArray = new Array()
        resArray[0] = res
        resArray[1] = ch.toString()
        return resArray


    }
    // 二进制按位取反
    static reverseInBit(binStr) {

        var res = ''
        for (let i = 0; i < binStr.length; i++) {
            if (binStr[i].indexOf('0') != -1) {
                res += '1'
            } else {
                res += '0'
            }
        }
        return res
    }

    // 十六进制字符串转成二进制字符串,原码转原码，补码转补码，原码可带符号
    static hexToBinComplement(hexStr, isOriginal, binWidth = 64) {
        console.log(hexStr, isOriginal)
        hexStr = hexStr.toString().replace('0x', '')
        var binStr = ''
        if (isOriginal) {
            var length
            var isNegative = hexStr[0] == '-'
            hexStr = hexStr.replace('-', '')
            length = hexStr.length
            binStr = BigInt(hexStr).toString(2)
            if (binStr.length > binWidth - 1) {
                console.log('hexToBinComplement error')
                return
            }
            if (isNegative) {
                // 负数的补码等于原码按位取反加一，不算符号位
                binStr = this.reverseInBit(binStr)
                binStr = this.binAdd(binStr, '01')
                binStr = '1' + binStr

            } else {
                binStr = '0' + binStr
            }

        } else {
            binStr = BigInt(hexStr).toString(2)
        }

        // console.log('hexComplementToBin',binStr)
        return this.binFillTobinWidth(binStr, binWidth)
    }


    static hexAdd(v1, v2, isOriginal1, isOriginal2, binWidth = 64) {
        // console.log('hexAdd',v1, v2)
        console.log(v1, v2, isOriginal1, isOriginal2)
        v1 = this.hexToBinComplement(v1, isOriginal1)
        v2 = this.hexToBinComplement(v2, isOriginal2)
        var ch

        var resArray = this.binAdd(v1, v2)
        // console.log('resBin', resArray[0])
        var res = BigInt(resArray[0]).toString(16)
        // console.log('res',res)
        return res

    }


    static bytes2hex(bytes) {
        var hex = ""
        var len = bytes.length

        for (let i = 0; i < len; i++) {
            let tmp, num = bytes[i];
            if (num < 0) {
                tmp = (255 + num + 1).toString(16);
            } else {
                tmp = num.toString(16);
            }
            if (tmp.length == 1) {
                tmp = "0" + tmp;
            }
            hex += tmp + ' ';

            // console.log('hex',hex)
        }
        return hex
    }



}

// 所有与指令相关的方法，做个封装
class InstHelper {

    inited
    supportInst

    // 基本都是涉及pc的，需要不断完善
    static testSupport(inst) {
        if (!InstHelper.inited) {
            InstHelper.inited = true
            InstHelper.supportInst = new Set()
            InstHelper.supportInst.add('add')
            InstHelper.supportInst.add('blx')
            InstHelper.supportInst.add('bl')
        }
        if (!InstHelper.is_pc_relative(inst)) {
            return true
        }
        if (InstHelper.supportInst.has(inst.mnemonic)) {
            return true
        } else {
            return false
        }
    }

   
    static is_pc_relative(inst) {

        if (inst.regsRead.includes('pc')) {
            return true
        }
        if (inst.regsWritten.includes('pc')) {
            return true
        }
        if (inst.opStr.includes('pc')) {
            return true
        }
        if (inst.groups.includes('call')) {
            return true
        }
        if (inst.groups.includes('branch_relative')) {
            return true
        }


        return false

    }

    // thumb or arm or arm64
    static getInstType(inst) {
        if (Process.arch == 'arm64') {
            return 'arm64'
        }
        for (let type of inst.groups) {
            if (type.toLowerCase() == 'thumb') {
                return 'thumb'
            } else if (type.toLowerCase() == 'arm') {
                return 'arm'
            } else {
                /*  */
            }
        }

    }

    // 获得内存操作数的地址,detail为异常中的包含寄存的上下文，或者任何包含了寄存器的上下文都行
    static getMemAddr(memOprand, detail) {
        // console.log(JSON.stringify(memOprand))
        // console.log(JSON.stringify(detail))
        // console.log(JSON.stringify(memOprand),JSON.stringify(detail))

        var base = detail[memOprand['base']]
        var numDisp = memOprand.disp
        // console.log(base, disp)
        // memAddr = BinSupport.hexAdd(base, disp,false,true)

        base = BigInt(base)
        var disp = BigInt(numDisp)
        var memAddr = base + disp

        // memAddr = BigInt(base.toString())+numDisp
        // console.log('memAddr', memAddr)
        return '0x' + memAddr.toString(16)
    }

    // 模拟执行，执行完之后会把结果修正到detail中
    static simulateInst(inst, detail) {
        console.log('simulateInst enter')
        switch (inst.mnemonic) {
            case 'add':
                console.log('simulateInst', inst.mnemonic)
                var tempRes = 0
                tempRes = tempRes.toString(16)
                for (let i = 1; i < inst.operands.length; i++) {
                    console.log(JSON.stringify(inst.operands[i]))
                    // 寄存器操作数
                    if (build_re('reg').test(inst.operands[i].type)) {
                        tempRes = BinSupport.hexAdd(tempRes, detail[inst.operands[i].value])
                    } else if (build_re('imm').test(inst.operands[i].type)) {
                        tempRes = BinSupport.hexAdd(tempRes, inst.operands[i].value.toString(16))
                    } else if (build_re('mem').test(inst.operands[i].type)) {
                        var addr = InstHelper.getMemAddr(inst.operands[i].value)
                        tempRes = BinSupport.hexAdd(tempRes, addr.readPointer())
                    } else {
                        console.log('simulateInst error', JSON.stringify(inst))
                    }
                }
                detail.context[inst.operands[0].value] = tempRes
                break
            case 'blx':
                console.log( inst.mnemonic)
                var uNextPc = ExceptionHook.getNextPc(parseInt(detail.address, 16))
                detail.context.pc = uNextPc
             
                console.log('detail.context.pc', detail.context.pc)
                break
            case 'bl':
                console.log( inst.mnemonic)
                var uNextPc = ExceptionHook.getNextPc(parseInt(detail.address, 16))
                console.log('uNextPc.toString(16)', uNextPc.toString(16))
                detail.context.pc = uNextPc
                // detail.context.pc = 0
                detail.context.lr = Number(detail.address)+4
                console.log('detail.context.pc', detail.context.pc)
                break
            default:
                console.log('暂未支持', inst.mnemonic)
                break
        }
    }

    static test() {
        var addr = Memory.alloc(4).writeU32(0xaf03)
        var inst = Instruction.parse(addr.add(1))
        var detail = { 'r7': '0xa23', 'sp': '0xa23' }
        console.log(JSON.stringify(inst))
        console.log(JSON.stringify(detail))
        InstHelper.simulateInst(inst, detail)
        console.log(JSON.stringify(detail))
    }


}

// 正经用的支持多线程异常hook 
class ExceptionHook {
    // 指令的存储借助c层，所以断点的设置和移除可以完全随时ctrl+s

    static init(base) {
        if (!base) {
            console.log('ExceptionHook init base null')
            return
        }
        ExceptionHook.getInst = new NativeFunction(base.base.add(0x4DC78), 'uint64', ['uint64'])
        ExceptionHook.setInst = new NativeFunction(base.base.add(0x4E054), 'void', ['uint64', 'uint64'])
        ExceptionHook.getNextPc = new NativeFunction(base.base.add(0x4DF44), 'uint64', ['uint64'])
        ExceptionHook.setNextPc = new NativeFunction(base.base.add(0x4E158), 'void', ['uint64', 'uint64'])
        ExceptionHook.handleNativeContext = new NativeFunction(base.base.add(0x460A4), 'void', ['pointer', 'pointer'])

        console.log('ExceptionHook init', ExceptionHook.getInst, ExceptionHook.setInst, ExceptionHook.getNextPc, ExceptionHook.setNextPc, ExceptionHook.handleNativeContext)
    }





    // 处理pc无关指令,原理是，修改detail.context.pc为新的自定义指令块，在自定义指令块中执行原指令，然后调回原始地址的下一条继续执行;
    // 注意thumb要给地址多加个1；还要注意malloc分配内存，不然自定义指令块会被释放掉
    static HandleNotPcInst(inst, detail) {
        // 注意这个inst是原指令，但是不是在原地址
        // console.log('inst.address', inst.address, inst)
        console.log('HandleNotPcInst enter')
        var uInst = ptr(inst.address).readU32()
        // 拷贝原指令到trampline
        var trampline = malloc(50)
        Memory.protect(trampline, 50, 'rwx')
        if (inst.size == 2) {
            trampline.writeU16(uInst)

        } else {
            trampline.writeU32(uInst)

        }

        switch (InstHelper.getInstType(inst)) {
            case 'arm':
                var armWriter = new ArmWriter(trampline)
                armWriter.skip(inst.size)
                armWriter.putBranchAddress(ptr(detail.address).add(inst.size))
                armWriter.flush()

            case 'thumb':
                var thumbWriter = new ThumbWriter(trampline)
                thumbWriter.skip(inst.size)
                thumbWriter.putLdrRegAddress('pc', ptr(detail.address).add(inst.size).add(1))
                // thumbWriter.putLdrRegAddress('pc', ptr(0x1111))
                thumbWriter.flush()
                // disasm(trampline.add(1), 1)
                // console.log(trampline, trampline.readByteArray(100))
                break
            case 'arm64':
                var arm64Writer = new Arm64Writer(trampline)
                arm64Writer.skip(inst.size)
                arm64Writer.putBranchAddress(ptr(detail.address).add(inst.size))
                arm64Writer.flush()
                break
            default:
                console.log('HandleNotPcInst error ')
                return

        }

        detail.context.pc = trampline.toString()
        // console.log('detail.context.pc', detail.context.pc)

    }


    // 处理涉及到pc指令
    static HandlePcInst(inst, detail) {
        InstHelper.simulateInst(inst, detail)
    }

    // 处理原始指令
    static handOriInst(inst, detail) {
        console.log('handOriInst enter')
        if (!InstHelper.is_pc_relative(inst)) {
            ExceptionHook.HandleNotPcInst(inst, detail)
        } else {
            ExceptionHook.HandlePcInst(inst, detail)
        }

    }


    // 断点时执行的逻辑
    static my_hander(detail) {
        console.log('\n', 'my_hander enter')
        console.log(JSON.stringify(detail))

        // dumpContext(detail)
        // console.log(ptr(detail.context.x20).readUtf8String())
        // console.log(ptr(detail.context.x0).readUtf8String())
        // console.log(ptr(detail.context.x1).readUtf8String())


    }
    static ExceptionHandler(detail) {

        // console.log("ExceptionHandler enter")
        if (detail.message.indexOf('access violation accessing') != -1) {
            // console.log(detail)
            return false
        }
        var cinst = ExceptionHook.getInst(parseInt(detail.context.pc, 16))
        var bpkt = ptr(detail.context.pc).readU32()

        var inst
        var minstAddr
        // 分类处理各个架构断点指令，拿出原指令并解析 Instruction.parse
        if (bpkt == 0xef9f0001) {
            // arm
            minstAddr = Memory.alloc(4).writeU32(cinst)
            inst = Instruction.parse(minstAddr)

        } else if (bpkt == 0xd420f060) {
            // arm64
            minstAddr = Memory.alloc(4).writeU32(cinst)
            inst = Instruction.parse(minstAddr)
        }
        else if (bpkt == 0xa000f7f0) {
            // thumb2
            minstAddr = Memory.alloc(4).writeU32(cinst)
            inst = Instruction.parse(minstAddr.add(1))
        }
        else {
            minstAddr = Memory.alloc(4).writeU16(cinst)
            inst = Instruction.parse(minstAddr.add(1))
        }

        ExceptionHook.my_hander(detail)

        ExceptionHook.handOriInst(inst, detail)

        return true
    }

    // 预处理，比如跳转指令，直接把跳到的地址记录到表里
    static prepareInst(inst) {
        // console.log('prepareInst enter')
        if (build_re('blx').test(inst.mnemonic)) {
            var next = parseInt(inst.opStr.replace('#', ''), 16)
            var addr = parseInt(inst.address, 16)
            ExceptionHook.setNextPc(addr, next)
        } else if (build_re('bl').test(inst.mnemonic)) {
            var next = parseInt(inst.opStr.replace('#', ''), 16)
            var addr = parseInt(inst.address, 16)
            ExceptionHook.setNextPc(addr, next)
        }
    }

    // 带thumb位的地址
    static set(addr) {

        // 查看map中是否有原始指令，有的话说明已经下了断点了，没有存储就会返回0
        var cinst = ExceptionHook.getInst(parseInt(addr, 16))
        console.log('cinst', cinst)

        if (cinst != 0) {
            console.log('ExceptionHook set', addr.toString(), '断点已经存在')
            return
        }
        var inst = Instruction.parse(addr)
        
        // 看看是否支持这条指令下断
        if (!InstHelper.testSupport(inst)) {
            console.log('ExceptionHook set 暂未支持', JSON.stringify(inst))
            return
        }

        // 预处理，比如记录下b指令跳转目标，放在一个map中
        ExceptionHook.prepareInst(inst)
        console.log(JSON.stringify(inst))
        console.log('ExceptionHook set', inst.address, inst)

       
        ExceptionHook.setInst(parseInt(inst.address, 16), ptr(inst.address).readU32())

        // 写入断点
        if (Process.arch == 'arm32') {
            if (inst.groups.includes('thumb1only')) {
                console.log('thumb1only')
                
                ptr(inst.address).writeU16(0xde01)
            } else if (inst.groups.includes('arm')) {
                console.log('arm')
                
                ptr(inst.address).writeU32(0xef9f0001)
            } else {
                console.log('thumb2')
                
                ptr(inst.address).writeU32(0xa000f7f0)
            }
        } else {
            console.log('arm64')
            
            ptr(inst.address).writeU32(0xd420f060)
        }

    }

    // 真实的地址，不包含thumb位
    static remove(addr) {
        addr = ptr(addr)
        if (!this.getInst(parseInt(addr.toString(), 16))) {
            console.log('ExceptionHook remove', addr.toString(), '断点不存在')
            return
        }
        console.log('this.getInst(parseInt(addr.toString(), 16))', this.getInst(parseInt(addr.toString(), 16)))
        console.log('ExceptionHook remove', addr)

        // 恢复断点处的真实指令
        addr.writeU32(this.getInst(parseInt(addr.toString(), 16)))

        this.setInst(parseInt(addr.toString(), 16), 0)
        console.log('ExceptionHook remove', addr)
        console.log('this.getInst(parseInt(addr.toString(), 16))', this.getInst(parseInt(addr.toString(), 16)))
    }


}






function hook_java() {

    Java.perform(function () {

        console.log(`Process.id, ${Process.id},Process.arch, ${Process.arch}`)


        var context = activity_thread_getApplication()
        // console.log(context.getCacheDir().getPath())

        var so = 'libgiao.so'

        var base = Process.findModuleByName(so)


        load_my_so(context)

        ExceptionHook.init(Process.findModuleByName('libdutil.so'))

        Process.setExceptionHandler(ExceptionHook.ExceptionHandler)

        var addr = base.base.add(0x5EE0)
    

        ExceptionHook.set(addr)

        // ExceptionHook.remove(addr.add(0xB8C))












        //perform
    })





}




//main
console.log('\n------------------------------------------------------------------------------')


hook_java()




console.log('------------------------------------------------------------------------------')
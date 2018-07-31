---------------------------------------------
--	Module:	string
--	Auth:	WZS
--	Date:	2018年03月03日
--	Desc:	为string新增了一些方法,如split,trim
---------------------------------------------

--	Func:	截取
--	Param:	string,string(截取符集合)
--	Return:	table
---------------------------------------------
function string.split(s,sep)
	local fields = {}  
    s:gsub("([^"..sep.."]+)",
	function(c)
		fields[#fields + 1] = c
	end)
    return fields
end

--	Func:	除前后空白符
--	Param:	string
--	Return:	string
---------------------------------------------
function string.trim(s)
	return (s:gsub("^%s*(.-)%s*$","%1"))
end

--	Func:	返回二进制数据表
--	Param:	string
--	Return:	table,number(真实字节长)
--	Desc:	每个键值对表示64bit,即8字节
--			依次从低字节向高字节排列
--			如"Man":
--			{
--				[1] = 01001101 01100001 01101110 00000000 00000000 00000000 00000000 00000000
--			}
---------------------------------------------
function string.bin(s)
	local rTab = {}
	local len = s:len()
	for i = 1,len do
		local index = (i - 1) // 8 + 1
		rTab[index] = rTab[index] or 0
		rTab[index] = rTab[index] | s:byte(i) << 56 - ((i - 1) % 8) * 8
	end
	return rTab,len
end




----------------------------------------MD5----------------------------------------
local HexTable = {"0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"}
local A = 0x67452301
local B = 0xefcdab89
local C = 0x98badcfe
local D = 0x10325476

local S11 = 7
local S12 = 12
local S13 = 17
local S14 = 22
local S21 = 5
local S22 = 9
local S23 = 14
local S24 = 20
local S31 = 4
local S32 = 11
local S33 = 16
local S34 = 23
local S41 = 6
local S42 = 10
local S43 = 15
local S44 = 21

local function F(x,y,z)
	return (x & y) | ((~x) & z)
end
local function G(x,y,z)
	return (x & z) | (y & (~z))
end
local function H(x,y,z)
	return x ~ y ~ z
end
local function I(x,y,z)
	return y ~ (x | (~z))
end
local function FF(a,b,c,d,x,s,ac)
	a = a + F(b,c,d) + x + ac
	a = (((a & 0xffffffff) << s) | ((a & 0xffffffff) >> 32 - s)) + b
	return a & 0xffffffff
end
local function GG(a,b,c,d,x,s,ac)
	a = a + G(b,c,d) + x + ac
	a = (((a & 0xffffffff) << s) | ((a & 0xffffffff) >> 32 - s)) + b
	return a & 0xffffffff
end
local function HH(a,b,c,d,x,s,ac)
	a = a + H(b,c,d) + x + ac
	a = (((a & 0xffffffff) << s) | ((a & 0xffffffff) >> 32 - s)) + b
	return a & 0xffffffff
end
local function II(a,b,c,d,x,s,ac)
	a = a + I(b,c,d) + x + ac
	a = (((a & 0xffffffff) << s) | ((a & 0xffffffff) >> 32 - s)) + b
	return a & 0xffffffff
end

--	Func:	填充字符串
--	Param:	string
--	Return:	table
--	Desc:	将字符串填充至 string.len(s)*8%512 == 448,多余部分填充一个1和n个0
--			并在最后追加原消息长度
--			一个string.byte()为一字节，每个键值对保存4字节
---------------------------------------------
local function MD5StringFill(s)
	local len = s:len()
	local mod512 = len * 8 % 512
	--需要填充的字节数
	local fillSize = (448 - mod512) // 8
	if mod512 > 448 then
		fillSize = (960 - mod512) // 8
	end

	local rTab = {}

	--记录当前byte在4个字节的偏移
	local byteIndex = 1
	for i = 1,len do
		local index = (i - 1) // 4 + 1
		rTab[index] = rTab[index] or 0
		rTab[index] = rTab[index] | (s:byte(i) << (byteIndex - 1) * 8)
		byteIndex = byteIndex + 1
		if byteIndex == 5 then
			byteIndex = 1
		end
	end
	--先将最后一个字节组成4字节一组
	--表示0x80是否已插入
	local b0x80 = false
	local tLen = #rTab
	if byteIndex ~= 1 then
		rTab[tLen] = rTab[tLen] | 0x80 << (byteIndex - 1) * 8
		b0x80 = true
	end

	--将余下的字节补齐
	for i = 1,fillSize // 4 do
		if not b0x80 and i == 1 then
			rTab[tLen + i] = 0x80
		else
			rTab[tLen + i] = 0x0
		end
	end

	--后面加原始数据bit长度
	local bitLen = math.floor(len * 8)
	tLen = #rTab
	rTab[tLen + 1] = bitLen & 0xffffffff
	rTab[tLen + 2] = bitLen >> 32

	return rTab
end

--	Func:	计算MD5
--	Param:	string
--	Return:	string
---------------------------------------------
function string.md5(s)
	--填充
	local fillTab = MD5StringFill(s)
	local result = {A,B,C,D}

	for i = 1,#fillTab // 16 do
		local a = result[1]
		local b = result[2]
		local c = result[3]
		local d = result[4]
		local offset = (i - 1) * 16 + 1
		--第一轮
		a = FF(a, b, c, d, fillTab[offset + 0], S11, 0xd76aa478)
		d = FF(d, a, b, c, fillTab[offset + 1], S12, 0xe8c7b756)
		c = FF(c, d, a, b, fillTab[offset + 2], S13, 0x242070db)
		b = FF(b, c, d, a, fillTab[offset + 3], S14, 0xc1bdceee)
		a = FF(a, b, c, d, fillTab[offset + 4], S11, 0xf57c0faf)
		d = FF(d, a, b, c, fillTab[offset + 5], S12, 0x4787c62a)
		c = FF(c, d, a, b, fillTab[offset + 6], S13, 0xa8304613)
		b = FF(b, c, d, a, fillTab[offset + 7], S14, 0xfd469501)
		a = FF(a, b, c, d, fillTab[offset + 8], S11, 0x698098d8)
		d = FF(d, a, b, c, fillTab[offset + 9], S12, 0x8b44f7af)
		c = FF(c, d, a, b, fillTab[offset + 10], S13, 0xffff5bb1)
		b = FF(b, c, d, a, fillTab[offset + 11], S14, 0x895cd7be)
		a = FF(a, b, c, d, fillTab[offset + 12], S11, 0x6b901122)
		d = FF(d, a, b, c, fillTab[offset + 13], S12, 0xfd987193)
		c = FF(c, d, a, b, fillTab[offset + 14], S13, 0xa679438e)
		b = FF(b, c, d, a, fillTab[offset + 15], S14, 0x49b40821)

		--第二轮
		a = GG(a, b, c, d, fillTab[offset + 1], S21, 0xf61e2562)
		d = GG(d, a, b, c, fillTab[offset + 6], S22, 0xc040b340)
		c = GG(c, d, a, b, fillTab[offset + 11], S23, 0x265e5a51)
		b = GG(b, c, d, a, fillTab[offset + 0], S24, 0xe9b6c7aa)
		a = GG(a, b, c, d, fillTab[offset + 5], S21, 0xd62f105d)
		d = GG(d, a, b, c, fillTab[offset + 10], S22, 0x2441453)
		c = GG(c, d, a, b, fillTab[offset + 15], S23, 0xd8a1e681)
		b = GG(b, c, d, a, fillTab[offset + 4], S24, 0xe7d3fbc8)
		a = GG(a, b, c, d, fillTab[offset + 9], S21, 0x21e1cde6)
		d = GG(d, a, b, c, fillTab[offset + 14], S22, 0xc33707d6)
		c = GG(c, d, a, b, fillTab[offset + 3], S23, 0xf4d50d87)
		b = GG(b, c, d, a, fillTab[offset + 8], S24, 0x455a14ed)
		a = GG(a, b, c, d, fillTab[offset + 13], S21, 0xa9e3e905)
		d = GG(d, a, b, c, fillTab[offset + 2], S22, 0xfcefa3f8)
		c = GG(c, d, a, b, fillTab[offset + 7], S23, 0x676f02d9)
		b = GG(b, c, d, a, fillTab[offset + 12], S24, 0x8d2a4c8a)

		--第三轮
		a = HH(a, b, c, d, fillTab[offset + 5], S31, 0xfffa3942)
		d = HH(d, a, b, c, fillTab[offset + 8], S32, 0x8771f681)
		c = HH(c, d, a, b, fillTab[offset + 11], S33, 0x6d9d6122)
		b = HH(b, c, d, a, fillTab[offset + 14], S34, 0xfde5380c)
		a = HH(a, b, c, d, fillTab[offset + 1], S31, 0xa4beea44)
		d = HH(d, a, b, c, fillTab[offset + 4], S32, 0x4bdecfa9)
		c = HH(c, d, a, b, fillTab[offset + 7], S33, 0xf6bb4b60)
		b = HH(b, c, d, a, fillTab[offset + 10], S34, 0xbebfbc70)
		a = HH(a, b, c, d, fillTab[offset + 13], S31, 0x289b7ec6)
		d = HH(d, a, b, c, fillTab[offset + 0], S32, 0xeaa127fa)
		c = HH(c, d, a, b, fillTab[offset + 3], S33, 0xd4ef3085)
		b = HH(b, c, d, a, fillTab[offset + 6], S34, 0x4881d05)
		a = HH(a, b, c, d, fillTab[offset + 9], S31, 0xd9d4d039)
		d = HH(d, a, b, c, fillTab[offset + 12], S32, 0xe6db99e5)
		c = HH(c, d, a, b, fillTab[offset + 15], S33, 0x1fa27cf8)
		b = HH(b, c, d, a, fillTab[offset + 2], S34, 0xc4ac5665)

		--第四轮
		a = II(a, b, c, d, fillTab[offset + 0], S41, 0xf4292244)
		d = II(d, a, b, c, fillTab[offset + 7], S42, 0x432aff97)
		c = II(c, d, a, b, fillTab[offset + 14], S43, 0xab9423a7)
		b = II(b, c, d, a, fillTab[offset + 5], S44, 0xfc93a039)
		a = II(a, b, c, d, fillTab[offset + 12], S41, 0x655b59c3)
		d = II(d, a, b, c, fillTab[offset + 3], S42, 0x8f0ccc92)
		c = II(c, d, a, b, fillTab[offset + 10], S43, 0xffeff47d)
		b = II(b, c, d, a, fillTab[offset + 1], S44, 0x85845dd1)
		a = II(a, b, c, d, fillTab[offset + 8], S41, 0x6fa87e4f)
		d = II(d, a, b, c, fillTab[offset + 15], S42, 0xfe2ce6e0)
		c = II(c, d, a, b, fillTab[offset + 6], S43, 0xa3014314)
		b = II(b, c, d, a, fillTab[offset + 13], S44, 0x4e0811a1)
		a = II(a, b, c, d, fillTab[offset + 4], S41, 0xf7537e82)
		d = II(d, a, b, c, fillTab[offset + 11], S42, 0xbd3af235)
		c = II(c, d, a, b, fillTab[offset + 2], S43, 0x2ad7d2bb)
		b = II(b, c, d, a, fillTab[offset + 9], S44, 0xeb86d391)

		--加入到之前计算的结果当中
        result[1] = result[1] + a
        result[2] = result[2] + b
        result[3] = result[3] + c
		result[4] = result[4] + d
		result[1] = result[1] & 0xffffffff
		result[2] = result[2] & 0xffffffff
		result[3] = result[3] & 0xffffffff
		result[4] = result[4] & 0xffffffff
	end

	--将Hash值转换成十六进制的字符串
	local retStr = ""
	for i = 1,4 do
		for _ = 1,4 do
			local temp = result[i] & 0x0F
			local str = HexTable[temp + 1]
			result[i] = result[i] >> 4
			temp = result[i] & 0x0F
			retStr = retStr .. HexTable[temp + 1] .. str
			result[i] = result[i] >> 4
		end
	end

	return retStr
end
----------------------------------------MD5----------------------------------------




----------------------------------------Base64----------------------------------------
local Base64Map = {}
local Base64CharMap = {}
local Base64Str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
for i = 1,64 do
	Base64Map[i - 1] = Base64Str:sub(i,i)
end
for i = 1,64 do
	Base64CharMap[Base64Str:sub(i,i):byte()] = i - 1
end

--	Func:	对table数据块转换为base64
--	Param:	table,number
--	Return: string
--	Desc:	table中每个键值对保存8字节，len表示实际字节长度
---------------------------------------------
local function Bin2Base64String(tab,len)
	--计算len%3
	local mod3 = len % 3
	--将tab补充为字节长度正好为3的倍数
	if len > 0 then
		tab[#tab + 1] = 0
		len = len + (3 - mod3) % 3
	else
		return ""
	end

	--记录上次剩余的字节数偏移
	local lastBtyeOffset = 0
	--记录上次的表索引
	local lastIndex = 0

	--返回的字符串
	local retStr = ""

	for i = 1,len // 3 do
		--每次取3字节，转换为4个base64
		--当前的8字节组剩余多少可用bit
		local leftBit = (8 - lastBtyeOffset) * 8
		--判断是否跳到下一索引
		-- local bJumpIndex = false
		-- if leftBit == 24 then bJumpIndex = true end
		if leftBit > 24 then leftBit = 24 end
		--计算能分解多少个完整的6bit
		local bit6Num = leftBit // 6
		--多余的二进制位
		local leftBitNum = leftBit % 6

		if lastBtyeOffset == 0 then
			lastIndex = lastIndex + 1
		end

		--先拼接完整的base64字符
		for k = 1,bit6Num do
			retStr = retStr .. Base64Map[tab[lastIndex] >> 64 - (lastBtyeOffset * 8 + k * 6) & 0x3f]
		end
		lastBtyeOffset = (lastBtyeOffset + bit6Num * 6 // 8) % 8

		if leftBitNum > 0 then
			--计算跨越8字节位的base64字符
			local tempBits = (tab[lastIndex] & 0x3f >> 6 - leftBitNum) << (6 - leftBitNum)
			lastIndex = lastIndex + 1
			lastBtyeOffset = 0
			tempBits = tempBits | tab[lastIndex] >> 58 + leftBitNum
			retStr = retStr .. Base64Map[tempBits]

			--二进制位偏移
			local lastBitOffset = 6 - leftBitNum
			if 3 - bit6Num ~= 0 then
				--下一个索引下剩余的base64字符
				for k = 1,3 - bit6Num do
					retStr = retStr .. Base64Map[tab[lastIndex] >> 64 - (lastBtyeOffset * 8 + k * 6 + lastBitOffset) & 0x3f]
				end
			end

			lastBtyeOffset = (lastBtyeOffset + ((3 - bit6Num) * 6 + lastBitOffset) // 8) % 8
		-- elseif bJumpIndex then
		-- 	lastIndex = lastIndex + 1
		end
	end
	if mod3 == 1 then
		retStr = retStr:sub(1,-3) .. "=="
	elseif mod3 == 2 then
		retStr = retStr:sub(1,-2) .. "="
	end
	return retStr
end
--	Func:	对base64二进制table数据块转换为bin
--	Param:	table,number
--	Return: table
--	Desc:	Base64binTable每个键值对的每个字节只能保存6bit有效位
--			将其转换保存8bit
---------------------------------------------
local function Base64Bin2Bin(tab,len)
	local binTab = {}

end
--	Func:	对base64二进制table数据块转换为string
--	Param:	table,number
--	Return: string[,string]
--	Desc:	table中每个键值对保存8字节，len表示实际字节长度
--			并不是所有base64都能转换为可见字符
--			解析失败返回nil,string(第二个string是解析失败前已经解析的字符串)
---------------------------------------------
local function Base64Bin2String(tab,len)
	if len == 0 then return "" end

	local retStr = ""
	for index = 1,len // 8 do
		local bin48 = 0
		for k = 1,8 do
			local byte = tab[index] >> 56 - ((k - 1) % 8) * 8 & 0xff
			if not Base64CharMap[byte] then
				return nil,retStr
			else
				byte = Base64CharMap[byte]
			end
			--将8个byte中的48个有效bit,组合成6个字节
			bin48 = bin48 | byte << 56 - ((k - 1) % 8) * 8 + 2 * k
		end
		for i = 1,6 do
			retStr = retStr .. string.char(bin48 >> 64 - i * 8 & 0xff)
		end
	end
	--计算结尾的最后一个键值对
	local bin = 0
	local tabLen = #tab
	local mod8 = len % 8
	for k = 1,mod8 do
		local byte = tab[tabLen] >> 56 - ((k - 1) % 8) * 8 & 0xff
		if not Base64CharMap[byte] then
			return nil,retStr
		else
			byte = Base64CharMap[byte]
		end
		--将mod8个byte中的mod8 * 6个有效bit,组合成几个字节
		bin = bin | byte << 56 - ((k - 1) % 8) * 8 + 2 * k
	end
	for i = 1,mod8 * 6 // 8 do
		retStr = retStr .. string.char(bin >> 64 - i * 8 & 0xff)
	end

	return retStr
end

--	Func:	对string转换为base64
--	Param:	string
--	Return: string
---------------------------------------------
function string.base64(str)
	local binTab,len = str:bin()
	return Bin2Base64String(binTab,len)
end

--	Func:	对base64转换为string
--	Param:	string
--	Return: string[,string]
--	Desc:	并不是所有base64都能转换为可见字符
--			解析失败返回nil,string(第二个string是解析失败前已经解析的字符串)
---------------------------------------------
function string.unbase64(str)
	--去掉最后的=
	if str:sub(-1,-1) == "=" then
		str = str:sub(1,-2)
		if str:sub(-1,-1) == "=" then
			str = str:sub(1,-2)
		end
	end
	local binTab,len = str:bin()
	return Base64Bin2String(binTab,len)
end
----------------------------------------Base64----------------------------------------




----------------------------------------TEA----------------------------------------
--	加密流程：
--	string.bin(str) -> binTab
--	for binTab do Encrypt64(bin64,key) end -> encryptBinTab
--	Bin2Base64String(encryptBinTab) -> encryptStr

--	解密流程：
--	string.bin(str) -> base64BinTab
--	Base64Bin2Bin(base64BinTab) -> binTab
--	for 

local TeaDelta = 0x9e3779b9
--轮数
local TeaRound = 32
local TeaSum = 0
for __ = 0,TeaRound do
	TeaSum = TeaSum + TeaDelta
end

--	Func:	对64bit块加密
--	Param:	number(64bit),number(key1 64bit),number(key2 64bit)
--	Return: number
--	Desc:	key共128bit
---------------------------------------------
local function Encrypt64(v,k1,k2)
	local y = v & 0xffffffff
	local z = v >> 32
	local sum = 0

	--保存Key
	local a = k1 & 0xffffffff
	local b = k1 >> 32
	local c = k2 & 0xffffffff
	local d = k2 >> 32
	--32次循环
	for _ = 1,TeaRound do
		sum = sum + TeaDelta

		y = y + ((((z << 4) + a) & 0xffffffff) ~ ((z + sum) & 0xffffffff) ~ (((z >> 5) + b) & 0xffffffff))
		z = z + ((((y << 4) + c) & 0xffffffff) ~ ((y + sum) & 0xffffffff) ~ (((y >> 5) + d) & 0xffffffff))
	end

	v = y
	v = v | (z << 32)

	return v
end

--	Func:	对64bit块解密
--	Param:	number(64bit),number(key1 64bit),number(key2 64bit)
--	Return: number
--	Desc:	key共128bit
---------------------------------------------
local function Decrypt64(v,k1,k2)
	local y = v & 0xffffffff
	local z = v >> 32
	local sum = TeaSum--0xC6EF3720

	--保存Key
	local a = k1 & 0xffffffff
	local b = k1 >> 32
	local c = k2 & 0xffffffff
	local d = k2 >> 32
	--32次循环
	for _ = 1,TeaRound do
		z = z - ((((y << 4) + c) & 0xffffffff) ~ ((y + sum) & 0xffffffff) ~ (((y >> 5) + d) & 0xffffffff))
		y = y - ((((z << 4) + a) & 0xffffffff) ~ ((z + sum) & 0xffffffff) ~ (((z >> 5) + b) & 0xffffffff))

		sum = sum - TeaDelta
	end

	v = y
	v = v | (z << 32)

	return v
end

--	Func:	由密码串生成2个8字节的密码
--	Param:	string
--	Return:	number,number
--	Desc:	密码是16字节,不足部分补\0
---------------------------------------------
local function TeaKeyNumber(sKey)
	local len = sKey:len()
	local k1 = 0
	local k2 = 0
	if len > 0 then
		for i = 1,16 do
			local byte = i <= len and sKey:byte(i) or 0
			if i <= 8 then
				k1 = k1 | byte << (i - 1) * 8
			else
				k2 = k2 | byte << (i - 9) * 8
			end
		end
	end
	return k1,k2
end


--	Func:	加密为二进制数据表
--	Param:	string(明文),string(密匙)
--	Return:	talbe,number(真实字节长)
--	Desc:	密匙长度为16,若不足16,自动由\0补齐
---------------------------------------------
function string.encrypt2bin(s,sKey)
	--字符串分解为可操作的数据表
	local binTab,len = s:bin()
	--密文表
	local encryptTable = {}
	--密匙,2个64bit
	local k1,k2 = TeaKeyNumber(sKey)
	for k,v in pairs(binTab) do
		encryptTable[k] = Encrypt64(v,k1,k2)
	end
	return encryptTable,len
end

--	Func:	加密
--	Param:	string(明文),string(密匙)
--	Return:	string
--	Desc:	密匙长度为16,若不足16,自动由\0补齐
--			返回字符串为Base64
---------------------------------------------
function string.encrypt(s,sKey)
	--密文数据表
	local encryptTable,len = s:encrypt2bin(sKey)
	return Bin2Base64String(encryptTable,len)
end

--	Func:	解密
--	Param:	string(密文),string(密匙)
--	Return:	string
--	Desc:	解密失败返回nil
---------------------------------------------
function string.decrypt(s,sKey)
	if s == "" then return "" end
end
----------------------------------------TEA----------------------------------------
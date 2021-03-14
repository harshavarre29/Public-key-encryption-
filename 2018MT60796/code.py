import gmpy2
from gmpy2 import mpz

class hash_funtion:
    
    def return_hash(self,m):
        str=m
        A=str[0:64]
        B=str[64:128]
        C=str[128:192]
        D=str[192:256]
        #nlf
        E=""
        for i in range(0,64):
            t1=int(B[i])
            t2=int(C[i])
            t3=int(D[i])
            t4=int(A[i])
            if((((t1|t2)&t3) | (t1&(t2^t3)))^t4 ):
                E+="1"
            else:
                E+="0"
        S=D+E+B+C
        
        return S
        
    def de_hash(self,hash):
        str=hash
        D=str[0:64]
        E=str[64:128]
        B=str[128:192]
        C=str[192:256]
        A=""
        for i in range(0,64):
            t1=int(B[i])
            t2=int(C[i])
            t3=int(D[i])
            t4=int(E[i])
            if(((t1|t2)&t3) | (t1&(t2^t3)) ):
                if(t4):
                    A+="0"
                else:
                    A+="1"
            else:
                if(t4):
                    A+="1"
                else:
                    A+="0"
        S=A+B+C+D
        return S
    
class user1:#encrypts
    def __init__(self,hash,prime,prim_root,random_state):
        self.p=mpz(prime)
        self.g=mpz(prim_root)
        self.k1=gmpy2.mpz_random(random_state,prime)
        self.x1=gmpy2.powmod(self.g,self.k1,self.p)
        self.k11=gmpy2.mpz_random(random_state,prime)
        self.x11=gmpy2.powmod(self.g,self.k1,self.p)
        self.h=hash
    
    #returns g^k1(modp)    
    def key_sbox(self):
        return self.x1
    
    #common section key
    def c_s_k_sbox(self,x2):
        self.x21=gmpy2.powmod(x2,self.k1,self.p)
        if(gmpy2.is_even(self.x21)):
            self.e1=gmpy2.sub(self.x21,1)
            self.x(self.e1)
        else:
            self.e1=self.x21
            self.x(self.e1)
        self.d1=gmpy2.divm(1,self.e1,gmpy2.sub(self.p,1))
        
    
    def key_ske(self):
        return self.x11
    
    #common section key
    def c_s_k_ske(self,x2):
        self.x121=gmpy2.powmod(x2,self.k11,self.p)
        if(gmpy2.is_even(self.x121)):
            self.e2=gmpy2.sub(self.x121,1)
        else:
            self.e2=self.x121
        self.d2=gmpy2.divm(1,self.e2,gmpy2.sub(self.p,1))
            
    def x(self,e):
        t=e
        stri=str(t)
        l=len(stri)
        temp=""
        for i in range (0,l):
            t1=int(stri[i])
            if(t1<8):
                temp+="0"
                if(t1<4):
                    temp+="0"
                    if(t1<2):
                        temp+="0"
            temp+=bin(t1).replace("0b","")
        l=64-len(temp)
        for i in range (0,l):
            temp="0"+temp
        #temp is 56 bits
        PC1_left=[[57,49,41,33,25,17,9],[1,58,50,42,34,26,18],[10,2,59,51,43,35,27],[19,11,3,60,52,44,36]]
        PC1_right=[[63,55,47,39,31,23,15],[7,62,54,46,38,30,22],[14,6,61,53,45,37,29],[21,13,5,28,20,12,4]]
        C=""
        D=""
        for i in range (0,4):
            for j in range (0,7):
                C+=temp[PC1_left[i][(j+1)%7]]#left shift
                D+=temp[PC1_right[i][(j-1)%7]]#right shift
        temp1=C+D
        PC2=[[14,17,11,24,1,5,3,28],[15,6,21,10,23,19,12,4],[26,8,16,7,27,20,13,2],[41,52,31,37,47,55,30,40],[51,45,33,48,44,49,39,56],[34,53,46,42,50,36,29,32]]
        k=""
        for i in range (0,6):
            for j in range (0,8):
                k+=temp1[PC2[i][j]-1]   
        self.key1=k
        
    def substitution_box(self):
        print()
    
    def DES(self):
        IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57 ,49 ,41 ,33 ,25 ,17 ,9 ,1, 59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,63 ,55 ,47 ,39 ,31 ,23 ,15 ,7]
        l1=len(self.h)
        l=l1//64
        t1=self.h
        tem=""
        for i in range(0,l):
            for j in range (0,64):
                tem+=t1[i*64+IP[j]-1]
        t1=tem
        temp=""
        for i in range (0,l):
            C=t1[i*64:(i)*64+32]
            D=t1[i*64+32:(i+1)*64]
            E=self.sbox(D)
            temp+=D
            for j in range (0,32):
                temp+=str(int(E[j])^int((C[j])))
        return temp
        #temp is final encrypt    
        #it should be done with rig need to take care    
    
    def sbox(self,e):
        S=""
        st=e
        st=st+st[0:16]#expansion
        k=self.key1
        for i in range (0,48):
            S+=str(int(st[i])^int(k[i]))
        #xor
        S0=[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
        S1=[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
        S2=[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
        S3=[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
        S4=[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
        S5=[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
        S6=[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
        S7=[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
        s=[S0,S1,S2,S3,S4,S5,S6,S7]
        si=""
        for i in range (0,8):
            temp=S[i*6:(i+1)*6]
            a= int(temp[0])*2+int(temp[5])
            b= int(temp[1])*8+int(temp[2])*4+int(temp[3])*2+int(temp[4])
            c=s[i][a][b]
            if(c<8):
                si+="0"
                if(c<4):
                    si+="0"
                    if(c<2):
                        si+="0"
            si+=bin(c).replace("0b","")
        FP=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
        final=""
        for i in range(0,32):
            final+=si[FP[i]-1]
        return final
        
            
class user2:#decrypts
    def __init__(self,prime,prim_root,random_state):
        self.p=mpz(prime)
        self.g=mpz(prim_root)
        self.k1=gmpy2.mpz_random(random_state,prime)
        self.x1=gmpy2.powmod(self.g,self.k1,self.p)
        self.k11=gmpy2.mpz_random(random_state,prime)
        self.x11=gmpy2.powmod(self.g,self.k1,self.p)
        #self.h=hash
    
    #returns g^k1(modp)    
    def key_sbox(self):
        return self.x1
    
    #common section key
    def c_s_k_sbox(self,x2):
        self.x21=gmpy2.powmod(x2,self.k1,self.p)
        if(gmpy2.is_even(self.x21)):
            self.e1=gmpy2.sub(self.x21,1)
            self.y(self.e1)
        else:
            self.e1=self.x21
            self.y(self.e1)
        self.d1=gmpy2.divm(1,self.e1,gmpy2.sub(self.p,1))
        
    
    def key_ske(self):
        return self.x11
    
    #common section key
    def c_s_k_ske(self,x2):
        self.x121=gmpy2.powmod(x2,self.k11,self.p)
        if(gmpy2.is_even(self.x121)):
            self.e2=gmpy2.sub(self.x121,1)
        else:
            self.e2=self.x121
        self.d2=gmpy2.divm(1,self.e2,gmpy2.sub(self.p,1))
    
    def de_DES(self,hash):
        h=hash
        FP=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
        temp=""
        t1=self.sbox(h[0:32])
        t2=h[32:64]
        for j in range(0,32):
            temp+=str(int(t1[j])^int((t2[j])))
        temp+=h[0:32]
        final=""
        for i in range (0,64):
            final+=temp[FP[i]-1]
        #temp is hash.(64bits)
        return final
    
    def sbox(self,e):
        S=""
        st=e
        st=st+st[0:16]#expansion
        k=self.key1
        for i in range (0,48):
            S+=str(int(st[i])^int(k[i]))
        #xor
        S0=[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
        S1=[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
        S2=[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
        S3=[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
        S4=[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
        S5=[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
        S6=[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
        S7=[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
        s=[S0,S1,S2,S3,S4,S5,S6,S7]
        si=""
        for i in range (0,8):
            temp=S[i*6:(i+1)*6]
            a= int(temp[0])*2+int(temp[5])
            b= int(temp[1])*8+int(temp[2])*4+int(temp[3])*2+int(temp[4])
            c=s[i][a][b]
            if(c<8):
                si+="0"
                if(c<4):
                    si+="0"
                    if(c<2):
                        si+="0"
            si+=bin(c).replace("0b","")
        FP=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
        final=""
        for i in range(0,32):
            final+=si[FP[i]-1]
        return final
    
    def y(self,e):
        stri=str(e)
        l=len(stri)
        temp=""
        for i in range (0,l):
            t1=int(stri[i])
            if(t1<8):
                temp+="0"
                if(t1<4):
                    temp+="0"
                    if(t1<2):
                        temp+="0"
            temp+=bin(t1).replace("0b","")
        l=64-len(temp)
        for i in range (0,l):
            temp="0"+temp
        #temp is 56 bits
        PC1_left=[[57,49,41,33,25,17,9],[1,58,50,42,34,26,18],[10,2,59,51,43,35,27],[19,11,3,60,52,44,36]]
        PC1_right=[[63,55,47,39,31,23,15],[7,62,54,46,38,30,22],[14,6,61,53,45,37,29],[21,13,5,28,20,12,4]]
        C=""
        D=""
        for i in range (0,4):
            for j in range (0,7):
                C+=temp[PC1_left[i][(j+1)%7]]#left shift
                D+=temp[PC1_right[i][(j-1)%7]]#right shift
        temp1=C+D
        PC2=[[14,17,11,24,1,5,3,28],[15,6,21,10,23,19,12,4],[26,8,16,7,27,20,13,2],[41,52,31,37,47,55,30,40],[51,45,33,48,44,49,39,56],[34,53,46,42,50,36,29,32]]
        k=""
        for i in range (0,6):
            for j in range (0,8):
                k+=temp1[PC2[i][j]-1]   
        self.key1=k
        

    
if __name__=='__main__':
    m="INDIA IS MY COUNTRY"#message
    prime=1283
    prim_root=28
    print("given message:",m)
    print("given prime:" , prime)
    print("given genrator:",prim_root)
    print("")
    l=len(m)*5;
    t1=l//256
    t2=256*(t1+1)-l #extra spots to be filled by space that is 28=11100(5bits)
    st=m
    for i in range (0,t2//5+1):
        st+=" "
    l=len(st)
    s=""
    for i in range(0,l):
        #print(i)
        if(ord(st[i])==32):
            s+=bin(27).replace("0b","")
        elif(ord(st[i])==46):
            s+=bin(28).replace("0b","")
        elif(ord(st[i])==63):
            s+=bin(29).replace("0b","")
        elif(65<=ord(st[i])<=90):
            temp=ord(st[i])-65
            if(temp<16):
                s+="0"
                if(temp<8):
                    s+="0"
                    if(temp<4):
                        s+="0"
                        if(temp<2):
                            s+="0"
            s+=bin(temp).replace("0b","")
    t3=len(s)//256
    hash_s=""
    de_hash=""
    for i in range(0,t3):
        subs=s[i*256:256*(i+1)]
        hash=hash_funtion()
        t11=hash.return_hash(subs)
        hash_s+=t11
    print("hash of the message:",hash_s)    
    print("")
    random_state=gmpy2.random_state()
    user1= user1(hash_s,prime,prim_root,random_state)
    user2= user2(prime,prim_root,random_state)
    key1=user1.key_sbox()
    key2=user2.key_sbox()
    user1.c_s_k_sbox(key2)
    user2.c_s_k_sbox(key1)
    encr_hash=user1.DES()
    length=len(encr_hash)//64
    print("encrypted hash recived by user2:",encr_hash)
    print("")
    decr_hash=""
    for i in range(0,length):
        temp=encr_hash[i*64:i*64+64]
        decr_hash+=user2.de_DES(temp)
    
    for i in range(0,t3):
        t11=decr_hash[i*256:(i+1)*256]
        de_hash+=hash.de_hash(t11)
    print("deciphered hash by user2 :",de_hash)
    print("")
    l2=len(de_hash)//5
    encrypted=""
    for i in range(0,l2):
        s=de_hash[i*5:i*5+5]
        p=int(s[0])*16+int(s[1])*8+int(s[2])*4+int(s[3])*2+int(s[4])
        if(0<=p<=25):
            encrypted+=chr(p+65)
        elif(p==26):
            encrypted+="."
        elif(p==27):
            encrypted+=" "
        elif(p==28):
            encrypted+="?"
    print("final deciphered message read by user2:",encrypted)    
    print("")    
    
/* OpenCL C 1.2 source. The NVIDIA driver JITs this to native GPU assembly.
 * Kept as C string literals so z23-gpu-miner.exe is a single-file runtime. */
static const char z23_gpu_equihash_kernel_source_0[] =
"#define NB (1u<<20)\n"
"#define NS 64u\n"
"#define MASK 63u\n"
"#define MAXS 8u\n"
"__constant ulong IV[8]={0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL};\n"
"__constant uchar S[192]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3};\n"
"ulong rr(ulong x,uint n){return rotate(x,(ulong)(64u-n));}\n"
"ulong ld(__private const uchar*p){ulong x=0;for(uint i=0;i<8;i++)x|=((ulong)p[i])<<(8u*i);return x;}\n"
"void st(__private uchar*p,ulong x){for(uint i=0;i<8;i++)p[i]=(uchar)(x>>(8u*i));}\n"
"#define G(a,b,c,d,x,y) a=a+b+x;d=rr(d^a,32);c=c+d;b=rr(b^c,24);a=a+b+y;d=rr(d^a,16);c=c+d;b=rr(b^c,63)\n"
"void comp(__private ulong*h,__private const uchar*b,ulong t0,ulong t1,ulong f0){ulong m[16],v[16];for(uint i=0;i<16;i++)m[i]=ld(b+8*i);for(uint i=0;i<8;i++){v[i]=h[i];v[i+8]=IV[i];}v[12]^=t0;v[13]^=t1;v[14]^=f0;for(uint r=0;r<12;r++){uint q=16*r;G(v[0],v[4],v[8],v[12],m[S[q]],m[S[q+1]]);G(v[1],v[5],v[9],v[13],m[S[q+2]],m[S[q+3]]);G(v[2],v[6],v[10],v[14],m[S[q+4]],m[S[q+5]]);G(v[3],v[7],v[11],v[15],m[S[q+6]],m[S[q+7]]);G(v[0],v[5],v[10],v[15],m[S[q+8]],m[S[q+9]]);G(v[1],v[6],v[11],v[12],m[S[q+10]],m[S[q+11]]);G(v[2],v[7],v[8],v[13],m[S[q+12]],m[S[q+13]]);G(v[3],v[4],v[9],v[14],m[S[q+14]],m[S[q+15]]);}for(uint i=0;i<8;i++)h[i]^=v[i]^v[i+8];}\n"
"uint tree(uint b,uint a,uint c){return((b<<6)|a)<<6|c;}uint tb(uint t){return t>>12;}uint ta(uint t){return(t>>6)&MASK;}uint tc(uint t){return t&MASK;}\n"
"size_t p0(uint b,uint s,uint hf){return((size_t)b*NS+s)*7u+hf;}size_t p1(uint b,uint s,uint hf){return((size_t)b*NS+s)*6u+hf;}\n"
"uchar hb(__global uint*p,uint word,uint byte){return(uchar)(p[word+(byte>>2)]>>(8u*(byte&3u)));}\n"
"uint bid3(uchar a,uchar b,uchar c){return((((uint)a<<8)|b)<<4)|(c>>4);}\n"
"__kernel void d0(__global const ulong*ih,__global const ulong*it,__global const uchar*ib,uint blen,uint base,__global uint*h0,__global uint*cnt){uint z=base+get_global_id(0);if(z>=(1u<<24))return;ulong h[8];uchar b[128];for(uint i=0;i<8;i++)h[i]=ih[i];for(uint i=0;i<128;i++)b[i]=i<blen?ib[i]:(uchar)0;b[blen]=(uchar)z;b[blen+1]=(uchar)(z>>8);b[blen+2]=(uchar)(z>>16);b[blen+3]=(uchar)(z>>24);ulong t0=it[0]+blen+4u, t1=it[1]+(t0<it[0]);comp(h,b,t0,t1,~(ulong)0);uchar out[48];for(uint i=0;i<6;i++)st(out+8*i,h[i]);for(uint sub=0;sub<2;sub++){__private uchar*ph=out+24u*sub;uint buck=bid3(ph[0],ph[1],ph[2]);uint sl=atomic_inc(cnt+buck);if(sl<NS){size_t p=p0(buck,sl,0);h0[p]=2u*z+sub;__global uchar*dst=(__global uchar*)(h0+p+1u);for(uint j=2;j<24;j++)dst[j]=ph[j];}}}\n";

static const char z23_gpu_equihash_kernel_source_1[] =
"uint pw(uint r){return r==1?6u:r==2?5u:r==3?4u:r==4?4u:r==5?3u:r==6?2u:1u;}uint bo(uint r){return r==1?2u:r==2?1u:r==3?0u:r==4?3u:r==5?2u:1u;}\n"
"__kernel void dr(uint r,uint bbase,__global uint*h0,__global uint*h1,__global uint*cnt){uint buck=bbase+get_group_id(0),s=get_local_id(0);if(buck>=NB)return;uint inpar=(r-1u)&1u,outpar=r&1u;uint n=min(cnt[inpar*NB+buck],NS);if(s<n){uint prev=pw(r),off=bo(r),half0=(r-1u)/2u;size_t ps=inpar?p1(buck,s,half0):p0(buck,s,half0);uchar x=hb(inpar?h1:h0,(uint)ps+1u,off)&15u;for(uint a=0;a<s;a++){size_t pa=inpar?p1(buck,a,half0):p0(buck,a,half0);if((hb(inpar?h1:h0,(uint)pa+1u,off)&15u)!=x)continue;if((inpar?h1:h0)[pa+prev]==(inpar?h1:h0)[ps+prev])continue;uchar q0=hb(inpar?h1:h0,(uint)pa+1u,off+1u)^hb(inpar?h1:h0,(uint)ps+1u,off+1u);uchar q1=hb(inpar?h1:h0,(uint)pa+1u,off+2u)^hb(inpar?h1:h0,(uint)ps+1u,off+2u);uchar q2=hb(inpar?h1:h0,(uint)pa+1u,off+3u)^hb(inpar?h1:h0,(uint)ps+1u,off+3u);uint ob=bid3(q0,q1,q2),os=atomic_inc(cnt+outpar*NB+ob);if(os<NS){uint nw=pw(r+1u);size_t po=outpar?p1(ob,os,r/2u):p0(ob,os,r/2u);(outpar?h1:h0)[po]=tree(buck,a,s);for(uint j=0;j<nw;j++)(outpar?h1:h0)[po+1u+j]=(inpar?h1:h0)[pa+1u+(prev-nw)+j]^(inpar?h1:h0)[ps+1u+(prev-nw)+j];}}}barrier(CLK_GLOBAL_MEM_FENCE);if(s==0)cnt[inpar*NB+buck]=0;}\n"
"__kernel void dk(uint bbase,__global uint*h0,__global uint*cnt,__global uint*out,__global uint*nout){uint buck=bbase+get_group_id(0),s=get_local_id(0);if(buck>=NB)return;uint n=min(cnt[buck],NS);if(s<n){size_t ps=p0(buck,s,3);uchar x=hb(h0,(uint)ps+1u,0u)&15u;for(uint a=0;a<s;a++){size_t pa=p0(buck,a,3);if((hb(h0,(uint)pa+1u,0u)&15u)==x&&h0[pa+1u]==h0[ps+1u]){uint q=atomic_inc(nout);if(q<MAXS)out[q]=tree(buck,a,s);}}}barrier(CLK_GLOBAL_MEM_FENCE);if(s==0)cnt[buck]=0;}\n"
"uint rd(__global uint*h0,__global uint*h1,uint round,uint t){uint b=tb(t),s=ta(t);return(round&1u)?h1[p1(b,s,round/2u)]:h0[p0(b,s,round/2u)];}\n"
"__kernel void rebuild(__global uint*h0,__global uint*h1,__global uint*top,uint n,__global uint*proof){uint id=get_global_id(0);if(id>=n)return;uint a[128];a[0]=top[id];uint count=1;for(int r=6;r>=0;r--){for(int i=(int)count-1;i>=0;i--){uint t=a[i],b=tb(t),x=ta(t),y=tc(t);a[2*i]=rd(h0,h1,(uint)r,tree(b,x,0));a[2*i+1]=rd(h0,h1,(uint)r,tree(b,y,0));}count*=2;}for(uint span=2;span<=128;span*=2)for(uint p=0;p<128;p+=span)if(a[p]>a[p+span/2])for(uint j=0;j<span/2;j++){uint q=a[p+j];a[p+j]=a[p+span/2+j];a[p+span/2+j]=q;}for(uint i=0;i<128;i++)proof[id*128+i]=a[i];}\n";

static const char *const z23_gpu_equihash_kernel_sources[] = {
    z23_gpu_equihash_kernel_source_0,
    z23_gpu_equihash_kernel_source_1,
};

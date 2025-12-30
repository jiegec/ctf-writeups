# weird-app

```
by cleverbear57
Description

I made this weird android app, but all it gave me was this .apk file. Can you get the flag from it?
Attachments

weird.zip
```

Unzip the attachment, we can get a `app-debug.apk`. First, we can unzip the apk to find several .dex files: `classes.dex`, `classes2.dex` to `classes5.dex`.

Using dex2jar tool, we convert `classes4.dex` to `classes4-dex2jar.jar`:

```shell
$ d2j-dex2jar classes4.dex 
dex2jar classes4.dex -> ./classes4-dex2jar.jar
```

Then, we open the jar with JD-GUI and find the foollowing source:

```java
package com.example.test2;

import androidx.compose.material3.TextKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.RecomposeScopeImplKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.ui.Modifier;
import com.example.test2.ui.theme.ThemeKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata(d1 = {"\000\032\n\000\n\002\020\016\n\002\b\002\n\002\020\002\n\002\b\002\n\002\030\002\n\002\b\004\032\016\020\000\032\0020\0012\006\020\002\032\0020\001\032\037\020\003\032\0020\0042\006\020\005\032\0020\0012\b\b\002\020\006\032\0020\007H\007¢\006\002\020\b\032\r\020\t\032\0020\004H\007¢\006\002\020\n¨\006\013"}, d2 = {"transformFlag", "", "flag", "Greeting", "", "name", "modifier", "Landroidx/compose/ui/Modifier;", "(Ljava/lang/String;Landroidx/compose/ui/Modifier;Landroidx/compose/runtime/Composer;II)V", "GreetingPreview", "(Landroidx/compose/runtime/Composer;I)V", "app_debug"}, k = 2, mv = {2, 0, 0}, xi = 48)
public final class MainActivityKt {
  public static final void Greeting(String paramString, Modifier paramModifier, Composer paramComposer, int paramInt1, int paramInt2) {
    Intrinsics.checkNotNullParameter(paramString, "name");
    Composer composer = paramComposer.startRestartGroup(-1085550318);
    ComposerKt.sourceInformation(composer, "C(Greeting)P(1)71@2073L104:MainActivity.kt#8w8ms1");
    int i = paramInt1;
    int j = paramInt2 & 0x2;
    if (j != 0) {
      i |= 0x30;
    } else if ((paramInt1 & 0x30) == 0) {
      byte b;
      if (composer.changed(paramModifier)) {
        b = 32;
      } else {
        b = 16;
      } 
      i |= b;
    } 
    if ((i & 0x11) != 16 || !composer.getSkipping()) {
      if (j != 0)
        paramModifier = (Modifier)Modifier.Companion; 
      if (ComposerKt.isTraceInProgress())
        ComposerKt.traceEventStart(-1085550318, i, -1, "com.example.test2.Greeting (MainActivity.kt:70)"); 
      Modifier modifier = paramModifier;
      TextKt.Text--4IGK_g("Transformed flag: idvi+1{s6e3{)arg2zv[moqa905+", modifier, 0L, 0L, null, null, null, 0L, null, null, 0L, 0, false, 0, 0, null, null, composer, i & 0x70 | 0x6, 0, 131068);
      paramModifier = modifier;
      if (ComposerKt.isTraceInProgress()) {
        ComposerKt.traceEventEnd();
        paramModifier = modifier;
      } 
    } else {
      composer.skipToGroupEnd();
    } 
    ScopeUpdateScope scopeUpdateScope = composer.endRestartGroup();
    if (scopeUpdateScope != null)
      scopeUpdateScope.updateScope(new MainActivityKt$$ExternalSyntheticLambda1(paramString, paramModifier, paramInt1, paramInt2)); 
  }
  
  private static final Unit Greeting$lambda$0(String paramString, Modifier paramModifier, int paramInt1, int paramInt2, Composer paramComposer, int paramInt3) {
    Greeting(paramString, paramModifier, paramComposer, RecomposeScopeImplKt.updateChangedFlags(paramInt1 | 0x1), paramInt2);
    return Unit.INSTANCE;
  }
  
  public static final void GreetingPreview(Composer paramComposer, int paramInt) {
    paramComposer = paramComposer.startRestartGroup(428793000);
    ComposerKt.sourceInformation(paramComposer, "C(GreetingPreview)80@2253L46:MainActivity.kt#8w8ms1");
    if (paramInt != 0 || !paramComposer.getSkipping()) {
      if (ComposerKt.isTraceInProgress())
        ComposerKt.traceEventStart(428793000, paramInt, -1, "com.example.test2.GreetingPreview (MainActivity.kt:79)"); 
      ThemeKt.Test2Theme(false, false, ComposableSingletons$MainActivityKt.INSTANCE.getLambda-1$app_debug(), paramComposer, 384, 3);
      if (ComposerKt.isTraceInProgress())
        ComposerKt.traceEventEnd(); 
    } else {
      paramComposer.skipToGroupEnd();
    } 
    ScopeUpdateScope scopeUpdateScope = paramComposer.endRestartGroup();
    if (scopeUpdateScope != null)
      scopeUpdateScope.updateScope(new MainActivityKt$$ExternalSyntheticLambda0(paramInt)); 
  }
  
  private static final Unit GreetingPreview$lambda$1(int paramInt1, Composer paramComposer, int paramInt2) {
    GreetingPreview(paramComposer, RecomposeScopeImplKt.updateChangedFlags(paramInt1 | 0x1));
    return Unit.INSTANCE;
  }
  
  public static final String transformFlag(String paramString) {
    Intrinsics.checkNotNullParameter(paramString, "flag");
    String str = "";
    byte b = 0;
    int i = ((CharSequence)paramString).length();
    while (b < i) {
      byte b1 = 0;
      int j = ((CharSequence)"abcdefghijklmnopqrstuvwxyz").length();
      while (b1 < j) {
        String str1 = str;
        if ("abcdefghijklmnopqrstuvwxyz".charAt(b1) == paramString.charAt(b)) {
          char c = "abcdefghijklmnopqrstuvwxyz".charAt((b1 + b) % "abcdefghijklmnopqrstuvwxyz".length());
          str1 = str + c;
        } 
        b1++;
        str = str1;
      } 
      b1 = 0;
      j = ((CharSequence)"0123456789").length();
      while (b1 < j) {
        String str1 = str;
        if ("0123456789".charAt(b1) == paramString.charAt(b)) {
          char c = "0123456789".charAt((b * 2 + b1) % "0123456789".length());
          str1 = str + c;
        } 
        b1++;
        str = str1;
      } 
      b1 = 0;
      j = ((CharSequence)"!@#$%^&*()_+{}[]|").length();
      while (b1 < j) {
        String str1 = str;
        if ("!@#$%^&*()_+{}[]|".charAt(b1) == paramString.charAt(b)) {
          char c = "!@#$%^&*()_+{}[]|".charAt((b * b + b1) % "!@#$%^&*()_+{}[]|".length());
          str1 = str + c;
        } 
        b1++;
        str = str1;
      } 
      b++;
    } 
    return str;
  }
}


/* Location:              /home/jiegec/ctf/imaginaryctf2025/app-debug/classes4-dex2jar.jar!/com/example/test2/MainActivityKt.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */
```

Reverse the flag transformation:

```python
transformed = "idvi+1{s6e3{)arg2zv[moqa905+"
for i, ch in enumerate(transformed):
    if ch.islower():
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        j = alphabet.index(ch)
        j = (j - i) % len(alphabet)
        print(alphabet[j], end="")
    elif ch.isdigit():
        alphabet = "0123456789"
        j = alphabet.index(ch)
        j = (j - i * 2) % len(alphabet)
        print(alphabet[j], end="")
    else:
        alphabet = "!@#$%^&*()_+{}[]|"
        j = alphabet.index(ch)
        j = (j - i * i) % len(alphabet)
        print(alphabet[j], end="")
```

Flag: `ictf{1_l0v3_@ndr0id_stud103}`.

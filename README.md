自己cargo build --release    
加密到一半，如果遇到IO故障无法读取会崩出来，导致一半加了一半没加。    
因此最好用tarzst打包了再加密。

加密库从ring换成aws-lc-rs了。如果遇到编译莫名其妙的问题就注释掉直接换回ring。裸ring只需要一个gcc就可以编译    
ring的吞吐量不如aws-lc-rs，更换之后可以稍微增加一点性能。    
密钥的salt已经切换到argon2id。

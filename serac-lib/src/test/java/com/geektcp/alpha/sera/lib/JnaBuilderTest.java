package com.geektcp.alpha.sera.lib;

import java.io.File;

import com.sun.jna.Library;
import com.sun.jna.Native;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author tanghaiyang on 2020/5/8 16:42.
 */
@Slf4j
public class JnaBuilderTest {

    public interface ExampleJNA extends Library {
        int sum(int num1, int num2);
        void sumArray(int[] a, int[] b, int[] result, int size);
    }

    public static void main(String[] args) {
        // get lib folder from resource
        URL url = JnaBuilderTest.class.getClassLoader().getResource("lib");
        if (Objects.isNull(url)) {
            return;
        }
        File file = new File(url.getFile());

        // set jna.library.path to the path of lib
        System.setProperty("jna.library.path", file.getAbsolutePath());
        // load example.so from lib
        ExampleJNA example = Native.load("example", ExampleJNA.class);

        // call sum method from example library
        int a = 2;
        int b = 3;
        int result = example.sum(a, b);
        log.info(a + " + " + b + " = " + result);

        // example using arrays
        int size = 5;
        // input 2 integer arrays
        int[] listA = new int[]{1, 2, 3, 4, 5};
        int[] listB = new int[]{5, 4, 3, 2, 1};
        // output the sum of the arrays
        int[] listC = new int[size];
        example.sumArray(listA, listB, listC, size);
        log.info("A = " + Arrays.toString(listA));
        log.info("B = " + Arrays.toString(listB));
        log.info("A + B = " + Arrays.toString(listC));

    }
}
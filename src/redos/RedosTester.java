package redos;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.*;

import com.alibaba.fastjson.JSONObject;

import redos.regex.Analyzer;
import redos.regex.Matcher;
import redos.regex.Pattern;

public class RedosTester {
    public static void vulValidation(String inputPath, String outputPath) throws IOException {
        File attackInfo = new File(inputPath);
        if (attackInfo.isFile()) {
            FileInputStream inputStream = new FileInputStream(attackInfo.getPath());
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

            String attackInfoJson = null;
            String regex = null;
            String prefix = null;
            String attack_core = null;
            String suffix = null;
            int max_length = 128;
            double threshold = 1e8;

            File writeVul = new File(outputPath);
            writeVul.createNewFile();
            BufferedWriter outVul = new BufferedWriter(new FileWriter(writeVul));

            while ((attackInfoJson = bufferedReader.readLine()) != null) {
                JSONObject attackInfoObject = JSONObject.parseObject(attackInfoJson);
                regex = attackInfoObject.getString("regex");
                prefix = attackInfoObject.getString("prefix");
                attack_core = attackInfoObject.getString("pump");
                suffix = attackInfoObject.getString("suffix");
                int repeat_cnt = (max_length - prefix.length() - suffix.length()) / attack_core.length();
                String attack_string = "";
                if (repeat_cnt < 1) {
                    attack_string = prefix + suffix;
                    if (attack_string.length() > max_length)
                        attack_string = attack_string.substring(0, max_length - 1);
                } else {
                    String repeated = new String(new char[repeat_cnt]).replace("\0", attack_core);
                    attack_string = prefix + repeated + suffix;
                }
                System.out.print(regex + "\n");

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("pattern", regex);
                jsonObject.put("input", attack_string);
                System.out.print(jsonObject + "\n");

                try {
                    Pattern p = Pattern.compile(regex);
                    Matcher m = p.matcher(attack_string, new Trace(threshold, false));
                    Trace t = m.find();

                    System.out.print(t.getMatchSteps() + "\n");
                    if (t.getMatchSteps() > 1e5) {
                        outVul.write(regex + "\n");
                    }
                } catch (Exception e) {
                    System.out.print("0\n");
                }
            }

            inputStream.close();
            bufferedReader.close();
            outVul.flush();
            outVul.close();
        }
    }

    public static void testSingleRegex(String regex) throws Exception {
        int max_length = 128;
        double threshold = 1e5;
        BufferedWriter log = new BufferedWriter(new OutputStreamWriter(System.out));
        Pattern p = Pattern.compile(regex);
        Analyzer redosAnalyzer = new Analyzer(p, max_length);
        redosAnalyzer.doStaticAnalysis();
        redosAnalyzer.doDynamicAnalysis(log, -1, threshold);
        if (!redosAnalyzer.isVulnerable())
            System.out.print("Contains no vulnerablity\n");
        log.flush();
    }

    public static void testDataset() throws IOException {
        File testDir = new File("data");
        for (File file : testDir.listFiles()) {
            File writeVul = new File("vul-" + file.toPath().getFileName());
            writeVul.createNewFile();
            BufferedWriter outVul = new BufferedWriter(new FileWriter(writeVul));

            if (file.isFile()) {
                FileInputStream inputStream = new FileInputStream(file.getPath());
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

                String regex = null;
                int max_length = 128;
                double threshold = 1e5;
                int cnt = 0;
                // 线程池写法，使用一个16线程的线程池
                ExecutorService exec = Executors.newFixedThreadPool(16);
                while ((regex = bufferedReader.readLine()) != null) {
//                    System.out.println(regex);

                    // 限制执行时间
//                    new InterruptTest().getResult(regex, cnt);
//                    es.submit(new Task(regex));
                    String finalRegex = regex;
                    Callable<String> call = new Callable<String>() {
                        //                        public String call() throws Exception {
//                            //开始执行耗时操作
//                            testSingleRegexDIY(finalRegex);
//                            return "线程执行完成.";
//                        }
                        public String call() throws Exception {
                            try {
                                testSingleRegexDIY(finalRegex);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt(); //restore interrupted status
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            return "线程执行完成.";
                        }
                    };

                    Future<String> future = exec.submit(call);
                    try {
                        String obj = future.get(3, TimeUnit.SECONDS); //任务处理超时时间设为 1 秒
                        System.out.println("Success:" + cnt);
                    } catch (InterruptedException e) {
                        future.cancel(true);
                        System.out.println("方法执行中断:" + cnt + "\n" + e);
//                        e.printStackTrace();
                    } catch (ExecutionException e) {
                        future.cancel(true);
                        System.out.println("Execution异常:" + cnt + "\n" + e);
//                        e.printStackTrace();
                    } catch (TimeoutException e) {
                        future.cancel(true);
                        System.out.println("方法执行时间超时:" + cnt + "\n" + e);
//                        e.printStackTrace();
                    }

                    // 不限制执行时间
//					try {
////						System.out.print(regex + "\n");
////						Pattern p = Pattern.compile(regex);
////						Analyzer redosAnalyzer = new Analyzer(p, max_length);
////						redosAnalyzer.doStaticAnalysis();
////						redosAnalyzer.doDynamicAnalysis(outVul, cnt, threshold);
//						testSingleRegexDIY(regex);
//					} catch (Exception e) {
//						e.printStackTrace();
//					}

                    //无关
                    cnt += 1;
//                    if(cnt%500==0)System.out.println(cnt);
//                    else if(cnt>2500 && cnt%100==0)System.out.println(cnt);
//                    else if(cnt>2700 && cnt%10==0)
//                System.out.println(cnt);

//                    if(cnt%100==0)System.out.println(cnt);
                }
                exec.shutdown();
                inputStream.close();
                bufferedReader.close();
            }
            outVul.flush();
            outVul.close();

        }
        System.out.print("finished\n");
    }


    public static void testSingleRegexDIY(String regex) throws Exception {
        int max_length = 128;
        double threshold = 1e5;
        BufferedWriter log = new BufferedWriter(new OutputStreamWriter(System.out));
        Pattern p = Pattern.compile(regex);
        Analyzer redosAnalyzer = new Analyzer(p, max_length);
        // TODO: 解决.* √
        redosAnalyzer.doStaticAnalysisDIY();
        // TODO: 根据路径生成待匹配的字符串 √
        // TODO: 检测lookaround，如果不符合则重新生成（具体影响暂定）
        // 1. 生成lookaround节点的Set串
        // 2. 与Set路径的前几个取交集
        // TODO: match匹配 √
//		System.out.print("\nA vul:\n"+regex+"\n");
        for (Analyzer.VulStructure vul : redosAnalyzer.possibleVuls) {
//            StringBuffer attack_string = new StringBuffer(vul.prefix);
//            for (int i = 0; i < 100; i++) {
//                attack_string.append(vul.pump);
//            }
//            attack_string.append(vul.suffix);
////			System.out.print(attack_string+"\n");
            StringBuffer pump_string = new StringBuffer();
            int Len = vul.typeDIY == Analyzer.VulTypeDIY.POA ? 1000 : 100;
            while (pump_string.length() < Len) {
                pump_string.append(vul.pump);
            }
            try {
//				Pattern p = Pattern.compile(regex);
//                Matcher m = p.matcher(attack_string.toString(), new Trace(threshold, false));
                Matcher m = p.matcher(vul.prefix.toString() + pump_string.toString() + vul.suffix.toString(), new Trace(threshold, false));
                Trace t = m.find();

//				System.out.print(t.getMatchSteps() + "\n");
                if (t.getMatchSteps() > 1e5) {
//                    outVul.write(regex + "\n");
//                    outVul.write("Can be attacked");
                    System.out.println("Can be attacked:" + regex);
                    break;
                }
            } catch (Exception e) {
//                System.out.print("0\n");
                System.out.println("Run Failed:" + regex);
                e.printStackTrace();
                break;
//                System.out.println(e);
//                return;
            }
        }
    }

    public static void main(String[] args) throws Exception {
//        RedosTester.testSingleRegexDIY("zxc(abc)*bc(abc)*zxc");
//        RedosTester.testSingleRegexDIY("^\\s*[+-]?\\s*(?:\\d{1,3}(?:(,?)\\d{3})?(?:\\1\\d{3})*(\\.\\d*)?|\\.\\d+)\\s*$\n");
        RedosTester.testDataset();
    }

}

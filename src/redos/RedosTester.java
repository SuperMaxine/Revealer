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
			File writeVul = new File("result/vul-" + file.toPath().getFileName());
			writeVul.createNewFile();
			BufferedWriter outVul = new BufferedWriter(new FileWriter(writeVul));

			if (file.isFile()) {
				FileInputStream inputStream = new FileInputStream(file.getPath());
				BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

				String regex = null;
				int max_length = 128;
				double threshold = 1e5;
				int cnt = 0;
				while ((regex = bufferedReader.readLine()) != null) {
					try {
						System.out.print(regex + "\n");
						Pattern p = Pattern.compile(regex);
						Analyzer redosAnalyzer = new Analyzer(p, max_length);
						redosAnalyzer.doStaticAnalysis();
						redosAnalyzer.doDynamicAnalysis(outVul, cnt, threshold);
					} catch (java.util.regex.PatternSyntaxException e) {}
					cnt += 1;
				}

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
		// TODO: 根据路径生成待匹配的字符串
		// TODO: 检测lookaround，如果不符合则重新生成（具体影响暂定）
		// 1. 生成lookaround节点的Set串
		// 2. 与Set路径的前几个取交集
		// TODO: match匹配
		for(Analyzer.VulStructure vul : redosAnalyzer.possibleVuls) {
			StringBuffer attack_string=new StringBuffer(vul.prefix);
			for(int i = 0; i < 1000; i++){
				attack_string.append(vul.pump);
			}
			attack_string.append(vul.suffix);
			try {
//				Pattern p = Pattern.compile(regex);
				Matcher m = p.matcher(attack_string.toString(), new Trace(threshold, false));
				Trace t = m.find();

				System.out.print(t.getMatchSteps() + "\n");
				if (t.getMatchSteps() > 1e5) {
//					outVul.write(regex + "\n");
					System.out.print(regex + "\n");
				}
			} catch (Exception e) {
				System.out.print("0\n");
			}
		}
	}

	public static void main(String[] args) throws Exception {
		if (args.length == 1)
//			RedosTester.testSingleRegex(args[0]);
//			RedosTester.testSingleRegex("^(((a*a*)c)\\d)+$");
//			RedosTester.testSingleRegex(".[a-zA-Z]");
//			RedosTester.testSingleRegex("^(.|[^\"])*\"");
//			RedosTester.testSingleRegex("[adgjl]*[a-z1-9][A-Z]");
//			RedosTester.testSingleRegex("(abc)*[a-z]*");
//			RedosTester.testSingleRegex("((a*b)|(c*d)|(e*f*))*");

			RedosTester.testSingleRegexDIY("^123(((a*a*)c)\\d)+456$");

//			Test Len
//			RedosTester.testSingleRegex("m(?=a)n(?!b)x(?<=c)y(?<!d)z");
		else if (args.length == 2)
			RedosTester.vulValidation(args[0], args[1]);
		else
			RedosTester.testDataset();
	}

}

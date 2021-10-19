package redos;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import redos.regex.Analyzer;
import redos.regex.Pattern4Search;

public class RedosTester {
	public static void vulValidation(String inputPath, String outputPath) throws IOException {
//		File attackInfo = new File(inputPath);
//		if (attackInfo.isFile()) {
//			FileInputStream inputStream = new FileInputStream(attackInfo.getPath());
//			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
//
			String attackInfoJson = null;
			String regex = null;
			String prefix = null;
			String attack_core = null;
			String suffix = null;
			int max_length = 12800;
			int threshold = 100000;
//
//			File writeVul = new File(outputPath);
//			writeVul.createNewFile();
//			BufferedWriter outVul = new BufferedWriter(new FileWriter(writeVul));
//
//			while ((attackInfoJson = bufferedReader.readLine()) != null) {
//				JSONObject attackInfoObject = JSONObject.parseObject(attackInfoJson);
//				regex = attackInfoObject.getString("regex");
//				prefix = attackInfoObject.getString("prefix");
//				attack_core = attackInfoObject.getString("pump");
//				suffix = attackInfoObject.getString("suffix");
				regex = "a*a*";
				prefix = "";
				attack_core = "a";
				suffix = "!a!";
//				int repeat_cnt = (max_length - prefix.length() - suffix.length()) / attack_core.length();
//				String attack_string = "";
//				if (repeat_cnt < 1) {
//					attack_string = prefix + suffix;
//					if (attack_string.length() > max_length)
//						attack_string = attack_string.substring(0, max_length - 1);
//				} else {
//					String repeated = new String(new char[repeat_cnt]).replace("\0", attack_core);
//					attack_string = prefix + repeated + suffix;
//				}
//				System.out.print(regex + "\n");
//
//				JSONObject jsonObject = new JSONObject();
//				jsonObject.put("pattern", regex);
//				jsonObject.put("input", attack_string);
//				System.out.print(jsonObject + "\n");

				Pattern4Search p = Pattern4Search.compile(regex);
				Analyzer redosAnalyzer = new Analyzer(p, max_length);
				System.out.println(redosAnalyzer.checkResult(prefix, attack_core, suffix, max_length, threshold));


//				try {
//					Pattern p = Pattern.compile(regex);
//					Matcher m = p.matcher(attack_string, new Trace(threshold, false));
//
//					Trace t = m.matches2();
							//m.find();

//					System.out.print(t.getMatchSteps() + "\n");
//					if (t.getMatchSteps() > threshold) {
//						outVul.write(regex + "\n");
//						System.out.println("success");
//					}
//				} catch (Exception e) {
//					e.printStackTrace();
//					System.out.print("0\n");
//				}
			}

//			inputStream.close();
//			bufferedReader.close();
//			outVul.flush();
//			outVul.close();
//		}
//	}

	public static void testSingleRegex(String regex) throws Exception {
		int max_length = 128;
		int threshold = 10000;
		BufferedWriter log = new BufferedWriter(new OutputStreamWriter(System.out));
		Pattern4Search p = Pattern4Search.compile(regex);
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
				int threshold = 10000;
				int cnt = 0;
				while ((regex = bufferedReader.readLine()) != null) {
					try {
						System.out.print(regex + "\n");
						Pattern4Search p = Pattern4Search.compile(regex);
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

	public static void main(String[] args) throws Exception {
		long startTime = System.nanoTime();
//		String regex = "a+a+";
//		RedosTester.testSingleRegex(regex);
//		if (args.length == 1)
//			RedosTester.testSingleRegex(args[0]);
//		else if (args.length == 2)
			RedosTester.vulValidation("", "");
//		else
//			RedosTester.testDataset();

		long endTime = System.nanoTime();
		System.out.println((endTime - startTime)/1e9);
	}

}

package redos.regex;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.alibaba.fastjson.JSONObject;

import org.javatuples.Quartet;
import org.javatuples.Triplet;

import redos.regex.Pattern.Branch;
import redos.regex.Pattern.Node;
import redos.regex.Pattern.Ques;
import redos.utils.PatternUtils;

public class Analyzer {
    Pattern pattern;
    int maxLength;

    boolean possible_vulnerability;

    ArrayList<ArrayList<Node>> loopInLoop;
    ArrayList<ArrayList<Node>> branchInLoop;
    ArrayList<ArrayList<Node>> loopAfterLoop;
    ArrayList<ArrayList<Node>> diyPaths;
    ArrayList<ArrayList<Set<Integer>>> diyMatchs;
    ArrayList<ArrayList<ArrayList<Set<Integer>>>> allMatchs;
    ArrayList<ArrayList<overlap>> overlaps;
    Set<Node> loopNodes;

    public ArrayList<VulStructure> possibleVuls;

    String regex;

    public class VulStructure {
        public StringBuffer prefix;
        public StringBuffer pump;
        public StringBuffer suffix;
        public VulTypeDIY typeDIY;
        Driver suffixDriver = null;
        ArrayList<ArrayList<Node>> pathSharing;
        ArrayList<Node> fullPath;
        ArrayList<Node> path;
        Node path_start;
        Node path_end;
        Node suffixHead;
        Node curAtom;
        VulType type;
        Existance result = Existance.NOT_SURE;

        private class MatchGenerator {
            Node curNode = null;
            Map<Node, MatchGenerator> nextSliceSetUnsatisfied = null;
            Map<Node, MatchGenerator> nextSliceSetSatisfied = null;
            Map<Node, MatchGenerator> nextSliceSetMendatory = null;
            int min = 1;
            int max = 1;
            boolean isEnd = false;

            public MatchGenerator(Node node) {
                curNode = node;
                if (node == null) {
                    min = 0;
                    max = 0;
                } else {
                    min = pattern.getMinCount(node);
                    max = pattern.getMaxCount(node);
                    if (max > 10)
                        max = 10;
                }
            }

            public void addMendatoryCase(Node node, MatchGenerator generator) {
                if (nextSliceSetMendatory == null)
                    nextSliceSetMendatory = new HashMap<Node, MatchGenerator>();
                nextSliceSetMendatory.put(node, generator);
                if (!pattern.isSlice(curNode)) {
                    if (nextSliceSetSatisfied == null)
                        nextSliceSetSatisfied = new HashMap<Node, MatchGenerator>();
                    nextSliceSetSatisfied.put(node, generator);
                }
            }

            public void addUnsatisfiedCase(Node node, MatchGenerator generator) {
                if (nextSliceSetUnsatisfied == null)
                    nextSliceSetUnsatisfied = new HashMap<Node, MatchGenerator>();
                nextSliceSetUnsatisfied.put(node, generator);
                if (!pattern.isSlice(curNode)) {
                    if (nextSliceSetSatisfied == null)
                        nextSliceSetSatisfied = new HashMap<Node, MatchGenerator>();
                    nextSliceSetSatisfied.put(node, generator);
                }
            }

            public boolean isUnsatisfied(int cur) {
                return cur < min;
            }

            public boolean isSatisfied(int cur) {
                return (cur == min || cur > min) && cur < max;
            }
        }

        private class Driver {
            DirectedEngine engine = null;
            MatchGenerator curGenerator = null;
            StringBuffer matchingPath = null;
            Map<MatchGenerator, Integer> curCntSet = null;
            int cnt = 0;
            Set<Triplet<Driver, Node, MatchGenerator>> nextSlices = null;
            Set<Integer> nextCharSetFull = null;
            Map<Triplet<Driver, Node, MatchGenerator>, Set<Integer>> nextCharSetMap = null;
            boolean reachFinal = false;

            public Driver(DirectedEngine engineSource) {
                engine = engineSource;
                curGenerator = engine.headGenerator;
                matchingPath = new StringBuffer();
                curCntSet = new HashMap<MatchGenerator, Integer>();
            }

            public Driver(Driver oldDriver) {
                engine = oldDriver.engine;
                curGenerator = oldDriver.curGenerator;
                matchingPath = new StringBuffer();
                matchingPath.append(oldDriver.matchingPath);
                curCntSet = new HashMap<MatchGenerator, Integer>();
                curCntSet.putAll(oldDriver.curCntSet);
                cnt = oldDriver.cnt;
                reachFinal = oldDriver.reachFinal;
            }

            public void setAs(Driver newDriver) {
                engine = newDriver.engine;
                curGenerator = newDriver.curGenerator;
                matchingPath = new StringBuffer();
                matchingPath.append(newDriver.matchingPath);
                curCntSet = new HashMap<MatchGenerator, Integer>();
                curCntSet.putAll(newDriver.curCntSet);
                cnt = newDriver.cnt;
                reachFinal = newDriver.reachFinal;
            }

            private boolean driverSatisfied() {
                if (reachFinal)
                    return true;
                else if ((curGenerator == engine.finalGenerator && getState() != CurState.UNSATISFIED))
                    return true;
                else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)
                        && curGenerator.nextSliceSetSatisfied.containsKey(null)) {
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(null, curGenerator.nextSliceSetSatisfied.get(null));
                    if (newDriver.driverSatisfied())
                        return true;
                } else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)
                        && curGenerator.nextSliceSetMendatory.containsKey(null)) {
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(null, curGenerator.nextSliceSetMendatory.get(null));
                    if (newDriver.driverSatisfied())
                        return true;
                }
                return false;
            }

            public boolean notEnd() {
                return getState() == CurState.UNSATISFIED || hasNext(CurState.ONLEAVE);
            }

            public CurState getState() {
                if (curGenerator.isUnsatisfied(cnt))
                    return CurState.UNSATISFIED;
                else if (curGenerator.isSatisfied(cnt))
                    return CurState.SATISFIED;
                else
                    return CurState.ONLEAVE;
            }

            public boolean hasNext(CurState state) {
                switch (state) {
                    case UNSATISFIED:
                        return curGenerator.nextSliceSetUnsatisfied != null;
                    case SATISFIED:
                        return curGenerator.nextSliceSetSatisfied != null;
                    case ONLEAVE:
                        return curGenerator.nextSliceSetMendatory != null;
                }
                return false;
            }

            public void pushAny(CurState state) {
                switch (state) {
                    case UNSATISFIED:
                        Set<Node> nodeSet = curGenerator.nextSliceSetUnsatisfied.keySet();
                        Node nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetUnsatisfied.get(nextSliceNode));
                        break;
                    case SATISFIED:
                        nodeSet = curGenerator.nextSliceSetSatisfied.keySet();
                        nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetSatisfied.get(nextSliceNode));
                        break;
                    case ONLEAVE:
                        nodeSet = curGenerator.nextSliceSetMendatory.keySet();
                        nextSliceNode = nodeSet.iterator().next();
                        pushForward(nextSliceNode, curGenerator.nextSliceSetMendatory.get(nextSliceNode));
                        break;
                }
            }

            public void cntIncrease() {
                cnt += 1;
                curCntSet.put(curGenerator, cnt);
            }

            public void pushForward(Node sliceNode, MatchGenerator nextGeneratorSource) {
                boolean isEnd = curGenerator.isEnd; // get isEnd flag
                MatchGenerator nextGenerator = nextGeneratorSource;
                int lastCnt = 0;
                if (curCntSet.containsKey(nextGenerator) && isEnd) { // update curCntSet using isEnd
                    lastCnt = curCntSet.get(nextGenerator);
                    curCntSet.put(nextGenerator, lastCnt + 1);
                } else
                    curCntSet.put(nextGenerator, lastCnt);
                if (pattern.isSlice(sliceNode)) // upadate matching path
                    matchingPath.append(pattern.getSlice(sliceNode));

                cnt = curCntSet.get(nextGenerator); // update cur cnt
                curGenerator = nextGenerator; // update curGenerator = nextGeneratorSource
                // clear curCntSet if next generator reach a repetiton
                if (curGenerator == engine.headGenerator) {
                    reachFinal = true;
                    curCntSet.clear();
                }
                if (engine.notFinish(curGenerator, cnt)
                        && curGenerator.curNode == engine.directedPath.get(engine.index - 1))
                    engine.buildNext(curGenerator, cnt);
            }

            public String pushForward(Node sliceNode, MatchGenerator nextGeneratorSource, int ch) {
                String str = pattern.checkChar(sliceNode, ch);
                if (str == null)
                    return null;
                boolean isEnd = curGenerator.isEnd; // get isEnd flag
                MatchGenerator nextGenerator = nextGeneratorSource;
                int lastCnt = 0;
                if (curCntSet.containsKey(nextGenerator) && isEnd) { // update curCntSet using isEnd
                    lastCnt = curCntSet.get(nextGenerator);
                    curCntSet.put(nextGenerator, lastCnt + 1);
                } else if (sliceNode != null || isEnd)
                    curCntSet.put(nextGenerator, lastCnt + 1);
                else
                    curCntSet.put(nextGenerator, lastCnt);
                if (pattern.isSlice(sliceNode)) // upadate matching path
                    matchingPath.append(PatternUtils.convertString(ch) + str);
                cnt = curCntSet.get(nextGenerator); // update cur cnt
                curGenerator = nextGenerator; // update curGenerator = nextGeneratorSource
                // clear curCntSet if next generator reach a repetiton
                if (curGenerator == engine.headGenerator) {
                    reachFinal = true;
                    curCntSet.clear();
                }
                if (engine.notFinish(curGenerator, cnt)
                        && curGenerator.curNode == engine.directedPath.get(engine.index - 1))
                    engine.buildNext(curGenerator, cnt);
                return str;
            }

            private void update(Map<Node, MatchGenerator> map, MatchGenerator startGenerator) {
                if (curGenerator == startGenerator)
                    return;
                if (startGenerator == null)
                    startGenerator = curGenerator;
                if (map.containsKey(null) && map.size() == 1) {
                    if (curGenerator.isEnd && !(map == curGenerator.nextSliceSetUnsatisfied)) {
                        nextSlices = null;
                        return;
                    }
                    pushForward(null, map.get(null));
                    getNextSlices(startGenerator);
                    return;
                } else {
                    nextSlices = new HashSet<Triplet<Driver, Node, MatchGenerator>>();

                    for (Node node : map.keySet()) {
                        if (node == null && (!curGenerator.isEnd || curGenerator.nextSliceSetMendatory != map)) {
                            Driver newDriver = new Driver(this);
                            MatchGenerator nextGenerator = map.get(null);
                            newDriver.pushForward(null, nextGenerator);
                            newDriver.getNextSlices(startGenerator);
                            Set<Triplet<Driver, Node, MatchGenerator>> additionalSlice = newDriver.nextSlices;
                            if (additionalSlice != null)
                                nextSlices.addAll(additionalSlice);
                        } else if (node != null) {
                            Triplet<Driver, Node, MatchGenerator> triplet = new Triplet<Driver, Node, MatchGenerator>(
                                    this, node, map.get(node));
                            nextSlices.add(triplet);
                        }
                    }
                }
            }

            public void getNextSlices() {
                if (getState() == CurState.UNSATISFIED && hasNext(CurState.UNSATISFIED)) {
                    update(curGenerator.nextSliceSetUnsatisfied, null);
                } else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)) {
                    update(curGenerator.nextSliceSetMendatory, null);
                } else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)) {
                    update(curGenerator.nextSliceSetSatisfied, null);
                } else
                    nextSlices = null;
            }

            public void getNextSlices(MatchGenerator startGenerator) {
                if (getState() == CurState.UNSATISFIED && hasNext(CurState.UNSATISFIED)) {
                    update(curGenerator.nextSliceSetUnsatisfied, startGenerator);
                } else if (getState() == CurState.ONLEAVE && hasNext(CurState.ONLEAVE)) {
                    update(curGenerator.nextSliceSetMendatory, startGenerator);
                } else if (getState() == CurState.SATISFIED && hasNext(CurState.SATISFIED)) {
                    update(curGenerator.nextSliceSetSatisfied, startGenerator);
                } else
                    nextSlices = null;
            }

            public void getNextCharSet() {
                nextCharSetFull = new HashSet<Integer>();
                nextCharSetMap = new HashMap<Triplet<Driver, Node, MatchGenerator>, Set<Integer>>();
                for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                    Set<Integer> charSet = pattern.getMatchSet(triplet.getValue1());
                    if (charSet != null) {
                        nextCharSetMap.put(triplet, charSet);
                        nextCharSetFull.addAll(charSet);
                    }
                }
            }

            public String getShortestFailedMatch() {
                String failedMatch = "";
                ArrayList<Driver> allDrivers = new ArrayList<Driver>();
                allDrivers.add(this);
                int size = 1;

                for (int i = 0; i < size; i++) {
                    Driver driver = allDrivers.get(i);
                    driver.getNextSlices();
                    Set<Triplet<Driver, Node, MatchGenerator>> nextSlices = driver.nextSlices;
                    if (nextSlices == null) {
                        continue;
                    }
                    Set<Node> nextSliceNode = null;
                    for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                        if (nextSliceNode == null)
                            nextSliceNode = new HashSet<Node>();
                        nextSliceNode.add(triplet.getValue1());
                    }
                    String failedCore = pattern.getUnMatch(nextSliceNode);
                    if (failedCore != null) {
                        failedMatch = driver.matchingPath.toString() + failedCore;
                        break;
                    } else {
                        for (Triplet<Driver, Node, MatchGenerator> triplet : nextSlices) {
                            Driver curDriver = triplet.getValue0();
                            curDriver.pushForward(triplet.getValue1(), triplet.getValue2());
                            allDrivers.add(curDriver);
                            size += 1;
                        }
                    }
                }

                return failedMatch;
            }

            public void traverseToLast() {
                MatchGenerator coreGenerator = engine.headGenerator.nextSliceSetMendatory.values().iterator().next();
                ArrayList<Driver> genSet = new ArrayList<Driver>();
                curGenerator = coreGenerator;
                cnt = 0;
                curCntSet.clear();
                matchingPath.setLength(0);
                for (Node node : curGenerator.nextSliceSetUnsatisfied.keySet()) {
                    MatchGenerator nextGen = curGenerator.nextSliceSetUnsatisfied.get(node);
                    if (nextGen.isEnd && nextGen.nextSliceSetMendatory != null
                            && nextGen.nextSliceSetMendatory.containsValue(coreGenerator))
                        break;
                    Driver newDriver = new Driver(this);
                    newDriver.pushForward(node, nextGen);
                    genSet.add(newDriver);
                }
                int size = genSet.size();
                for (int i = 0; i < size; i++) {
                    Driver curDriver = genSet.get(i);
                    for (Node node : curDriver.curGenerator.nextSliceSetMendatory.keySet()) {
                        MatchGenerator nextGen = curDriver.curGenerator.nextSliceSetMendatory.get(node);
                        if (nextGen.isEnd && nextGen.nextSliceSetMendatory != null
                                && nextGen.nextSliceSetMendatory.containsValue(coreGenerator)) {
                            setAs(curDriver);
                            cnt = curGenerator.max;
                            break;
                        }
                        Driver newDriver = new Driver(curDriver);
                        newDriver.pushForward(node, curDriver.curGenerator.nextSliceSetMendatory.get(node));
                        genSet.add(newDriver);
                        size += 1;
                    }
                }
            }
        }

        public class DirectedEngine {
            ArrayList<Node> directedPath = null;
            Map<Node, MatchGenerator> allGenerators = null;
            MatchGenerator headGenerator = new MatchGenerator(null);
            MatchGenerator lastGenerator = headGenerator;
            MatchGenerator finalGenerator = null;
            int index = -1;
            boolean suffix = false;

            public DirectedEngine() {
                directedPath = new ArrayList<Node>();
                index = 0;
            }

            public DirectedEngine(ArrayList<Node> sourcePath) {
                directedPath = sourcePath;
                index = 0;
                buildToEnd();
            }

            public void buildToEnd() {
                while (index < directedPath.size()) {
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        continue;
                    }
                    lastGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    index += 1;
                }
                finalGenerator = lastGenerator;
            }

            public DirectedEngine(ArrayList<Node> sourcePath, boolean suffixSource) {
                suffix = suffixSource;
                directedPath = sourcePath;
                MatchGenerator tmpGenerator = headGenerator;
                index = 0;
                assert directedPath.size() > 0;
                while (directedPath.get(index).sub_next == null && directedPath.get(index).new_atoms == null
                        && !pattern.isSlice(directedPath.get(index)) && index < directedPath.size() - 1)
                    index += 1;
                do {
                    lastGenerator = tmpGenerator;
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        continue;
                    }
                    tmpGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    if (index == directedPath.size() - 1) {
                        if (suffix)
                            tmpGenerator.nextSliceSetMendatory = null;
                        else if (tmpGenerator != headGenerator) {
                            tmpGenerator.addMendatoryCase(null, headGenerator);
                            finalGenerator = tmpGenerator;
                        }
                    }
                    if (index == 0 && suffix)
                        tmpGenerator.min = 0;
                    index += 1;
                } while (notFinish(lastGenerator, 0));
                lastGenerator = tmpGenerator;
            }

            private void addFromEnginePath(DirectedEngine nextEngine) {
                directedPath.addAll(nextEngine.directedPath);
                if (finalGenerator != null) {
                    finalGenerator.nextSliceSetMendatory = null;
                    if (finalGenerator.nextSliceSetSatisfied != null
                            && finalGenerator.nextSliceSetSatisfied.containsKey(null))
                        finalGenerator.nextSliceSetSatisfied.remove(null);
                    finalGenerator = null;
                }
            }

            private void addFromEngine(DirectedEngine nextEngine) {
                Map<Node, MatchGenerator> map = nextEngine.headGenerator.nextSliceSetMendatory;
                if (map == null) {
                    finalGenerator.addMendatoryCase(null, headGenerator);
                    return;
                }
                MatchGenerator nextHead = map.values().iterator().next();
                lastGenerator = nextEngine.lastGenerator;
                finalGenerator.addMendatoryCase(null, nextHead);
                if (nextEngine.finalGenerator != null) {
                    nextEngine.finalGenerator.addMendatoryCase(null, headGenerator);
                    finalGenerator = nextEngine.finalGenerator;
                } else {
                    if (nextEngine.index < nextEngine.directedPath.size())
                        directedPath.addAll(nextEngine.directedPath);
                    index = index + nextEngine.index;
                    finalGenerator = null;
                }
            }

            private void buildNext(MatchGenerator lastGeneratorSource, int cnt) {
                MatchGenerator tmpGenerator = lastGeneratorSource;
                int count = 0;
                do {
                    lastGenerator = tmpGenerator;
                    Node node = directedPath.get(index);
                    Node next_node = null;
                    if (index < directedPath.size() - 1)
                        next_node = directedPath.get(index + 1);
                    if (next_node != null && (next_node == node.sub_next
                            || (node.new_atoms != null && Arrays.asList(node.new_atoms).contains(next_node)))) {
                        index += 1;
                        count = (lastGenerator == lastGeneratorSource) ? cnt : 0;
                        continue;
                    }
                    tmpGenerator = buildGenerators(node, lastGenerator, false, next_node);
                    if (index == directedPath.size() - 1) {
                        if (suffix)
                            tmpGenerator.nextSliceSetMendatory = null;
                        else if (tmpGenerator != headGenerator) {
                            tmpGenerator.addMendatoryCase(null, headGenerator);
                            finalGenerator = tmpGenerator;
                        }
                    }
                    index += 1;
                    count = (lastGenerator == lastGeneratorSource) ? cnt : 0;
                } while (notFinish(lastGenerator, count));
                lastGenerator = tmpGenerator;
            }

            private boolean notFinish(MatchGenerator generator, int cnt) {
                return !generator.isUnsatisfied(cnt) && generator.nextSliceSetMendatory == null
                        && index < directedPath.size();
            }

            public String getShortestMatching() {
                Driver driver = new Driver(this);
                while (driver.notEnd()) {
                    if (driver.getState() == CurState.UNSATISFIED) {
                        if (driver.hasNext(CurState.UNSATISFIED)) {
                            driver.pushAny(CurState.UNSATISFIED);
                        } else {
                            driver.cntIncrease();
                        }
                    } else {
                        driver.pushAny(CurState.ONLEAVE);
                    }
                }

                return driver.matchingPath.toString();
            }

            private MatchGenerator buildGenerators(Node node, MatchGenerator lastGeneratorTmp, boolean sub,
                                                   Node next_node) {
                Node lastNode = lastGeneratorTmp.curNode;
                MatchGenerator nextGenerator = lastGeneratorTmp;

                if (node.sub_next != null || (node.new_atoms != null && next_node != null) || pattern.isSlice(node)) { // cur
                    // is
                    // meaningful
                    if (allGenerators == null)
                        allGenerators = new HashMap<Node, MatchGenerator>();
                    MatchGenerator newGenerator = new MatchGenerator(node);
                    allGenerators.put(node, newGenerator);
                    if (node.direct_next != null && node.direct_next.direct_prev != node)
                        allGenerators.put(node.direct_next.direct_prev, newGenerator);
                    nextGenerator = newGenerator;
                    // got new generator

                    if (lastNode != null) { // last is meaningful
                        Node p = node;
                        while (p != lastNode && p != null) {
                            if (p == lastNode.direct_next || p == lastNode.sub_next
                                    || lastNode.new_atoms != null && Arrays.asList(lastNode.new_atoms).contains(p))
                                break;
                            p = p.direct_prev;
                        }
                        if (p == null || p == lastNode.direct_next) {
                            if (pattern.isSlice(node)) { // last generator is slice type
                                lastGeneratorTmp.addMendatoryCase(node, newGenerator);
                            } else { // equal to its next
                                lastGeneratorTmp.addMendatoryCase(null, newGenerator);
                            }

                        } else if (p == lastNode.sub_next
                                || lastNode.new_atoms != null && Arrays.asList(lastNode.new_atoms).contains(p)) {
                            if (pattern.isSlice(node)) { // last generator is slice type
                                lastGeneratorTmp.addUnsatisfiedCase(node, newGenerator);
                            } else { // equal to its next
                                lastGeneratorTmp.addUnsatisfiedCase(null, newGenerator);
                            }

                        } else { // TODO : backref condition

                        }
                    } else { // the begin Generator
                        if (pattern.isSlice(node)) { // last generator is slice type
                            lastGeneratorTmp.addMendatoryCase(node, newGenerator);
                        } else { // equal to its next
                            lastGeneratorTmp.addMendatoryCase(null, newGenerator);
                        }
                    }

                    if (sub) {
                        Node p = node.direct_next;
                        while (p != null) {
                            if (p.sub_next != null || p.new_atoms != null || pattern.isSlice(p))
                                break;
                            p = p.direct_next;
                        }

                        if (p == null) { // reach end of sub path
                            newGenerator.isEnd = true;
                            p = node;
                            while (p != null) {
                                if (p.direct_prev.direct_next != p)
                                    break;
                                p = p.direct_prev;
                            }
                            if (p != null) {
                                MatchGenerator subPathEnd = allGenerators.get(p.direct_prev);
                                newGenerator.addMendatoryCase(null, subPathEnd);
                            }
                        }
                    }
                }

                if (node.sub_next != null) {
                    if (sub)
                        buildGenerators(node.sub_next, nextGenerator, true, node.sub_next.direct_next);
                    else
                        buildGenerators(node.sub_next, nextGenerator, true, null);
                    if (node.sub_next == next_node) {
                        nextGenerator.nextSliceSetMendatory = nextGenerator.nextSliceSetSatisfied;
                        nextGenerator.min = 0;
                    }
                } else if (node.new_atoms != null && next_node != null) {
                    if (next_node.self != "BranchEnd") {
                        if (sub)
                            buildGenerators(next_node, nextGenerator, true, next_node.direct_next);
                        else
                            buildGenerators(next_node, nextGenerator, true, null);
                        nextGenerator.nextSliceSetMendatory = nextGenerator.nextSliceSetSatisfied;
                        nextGenerator.min = 0;
                    } else {
                        for (Node atom : node.new_atoms) {
                            buildGenerators(atom, nextGenerator, true, atom.direct_next);
                        }
                    }
                }

                if (sub && node.direct_next != null)
                    buildGenerators(node.direct_next, nextGenerator, true, node.direct_next.direct_next);

                return nextGenerator;
            }
        }

        public VulStructure(Node LoopNode, ArrayList<Set<Integer>> path, VulTypeDIY type) {
            initialize();
            typeDIY = type;
            path_start = LoopNode;
            prefix = new StringBuffer(getPrefix());

            Node p = path_start;
            while (p.direct_next == null)
                p = p.direct_prev;
            suffixHead = p.direct_next;
            suffix = new StringBuffer(getSuffix());
            pump = new StringBuffer();
            for (Set<Integer> s : path) {
                for (int c : s) {
                    pump.append((char) c);
                    break;
                }
            }
        }

        public VulStructure(Node LoopNode1, Node LoopNode2, ArrayList<Set<Integer>> path, VulTypeDIY type) {
            initialize();
            typeDIY = type;
            path_start = LoopNode1;
            prefix = new StringBuffer(getPrefix());

            Node p = LoopNode2;
            while (p.direct_next == null)
                p = p.direct_prev;
            suffixHead = p.direct_next;
            suffix = new StringBuffer(getSuffix());
            pump = new StringBuffer();
            for (Set<Integer> s : path) {
                for (int c : s) {
                    pump.append((char) c);
                    break;
                }
            }
        }

        public VulStructure(ArrayList<Node> sourcePath, VulType vulType) {
            initialize();
            type = vulType;
            path = sourcePath;
            path_start = path.get(0);
            path_end = path.get(path.size() - 1);
            path.remove(0);
            path.remove(path.size() - 1);
            if (path.size() > 0)
                addPath(path, true);
            switch (type) {
                case LOOP_IN_LOOP:
                    addPath(getDirectPath(path_end.direct_next), true);
                    addPath(getDirectPath(path_end.sub_next), false);
                    fullPath.addAll(path);
                    fullPath.add(path_end);
                    fullPath.addAll(getDirectPath(path_end.direct_next));
                    suffixHead = path_start;
                    break;
                case BRANCH_IN_LOOP:
                    addPath(getDirectPath(path_end.direct_next), true);
                    fullPath.addAll(path);
                    fullPath.add(path_end);
                    suffixHead = path_start;
                    break;
                case LOOP_AFTER_LOOP:
                    addPath(getDirectPath(path_start.sub_next), false);
                    addPath(getDirectPath(path_end.sub_next), false);
                    suffixHead = path_end;
                    break;
            }
        }

        private String getPrefix() {
            ArrayList<Node> prefixPath = new ArrayList<Node>();
            Node p;
            if (type != VulType.DIY) {
                p = path_start.direct_prev;
            } else {
                p = path_start;
            }
            if (p.self == "|")
                p = p.direct_prev;
            while (p != null) {
                prefixPath.add(0, p);
                p = p.direct_prev;
            }
            return getShortestMatching(prefixPath);
        }

        private boolean allSatisfied(Set<Driver> option) {
            for (Driver driver : option) {
                if (!driver.driverSatisfied())
                    return false;
            }
            return true;
        }

        private Set<Driver> getNewOption(Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> optionMap,
                                         int ch) {
            String sliceRemain = null;
            Driver driverRemain = null;
            Set<Driver> newDriverSet = new HashSet<Driver>();
            Set<Driver> nonSliceDriver = new HashSet<Driver>();

            for (Driver driver : optionMap.keySet()) {
                Quartet<Driver, Node, MatchGenerator, Set<Integer>> quartet = optionMap.get(driver);
                Driver newDriver = new Driver(quartet.getValue0());
                String str = newDriver.pushForward(quartet.getValue1(), quartet.getValue2(), ch);
                // push to next if is on leave without slice
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (str == null)
                    return null;
                else if (str != "") {
                    if (sliceRemain == null) {
                        sliceRemain = str;
                        driverRemain = newDriver;
                    } else if (sliceRemain.length() > str.length()
                            && sliceRemain.substring(0, str.length()).equals(str)) {
                        sliceRemain = sliceRemain.substring(str.length());
                        nonSliceDriver.add(newDriver);
                    } else if (sliceRemain.length() < str.length()
                            && sliceRemain.equals(str.substring(0, sliceRemain.length()))) {
                        sliceRemain = str.substring(sliceRemain.length());
                        nonSliceDriver.add(driverRemain);
                    } else if (!sliceRemain.equals(str))
                        return null;
                } else
                    nonSliceDriver.add(newDriver);
                newDriverSet.add(newDriver);
            }

            if (sliceRemain != null) {
                for (Driver driver : nonSliceDriver) {
                    // TODO: could have multiple possibilities, currently push to one.
                    if (!pushSliceToSatisfied(driver, sliceRemain))
                        return null;
                }
            }

            return newDriverSet;
        }

        private boolean pushSliceToSatisfied(Driver driver, String str) {
            while (driver.getState() == CurState.ONLEAVE && driver.curGenerator.nextSliceSetMendatory.size() == 1
                    && driver.curGenerator.nextSliceSetMendatory.containsKey(null))
                driver.pushForward(null, driver.curGenerator.nextSliceSetMendatory.get(null));
            driver.getNextSlices();
            Set<Triplet<Driver, Node, MatchGenerator>> option = driver.nextSlices;
            if (option == null)
                return false;
            int ch = str.charAt(0);
            for (Triplet<Driver, Node, MatchGenerator> triplet : option) {
                Driver newDriver = new Driver(driver);
                String remainStr = newDriver.pushForward(triplet.getValue1(), triplet.getValue2(), ch);
                while (newDriver.getState() == CurState.ONLEAVE
                        && newDriver.curGenerator.nextSliceSetMendatory.size() == 1
                        && newDriver.curGenerator.nextSliceSetMendatory.containsKey(null))
                    newDriver.pushForward(null, newDriver.curGenerator.nextSliceSetMendatory.get(null));
                if (remainStr != null) {
                    if (remainStr == "") {
                        if (str.length() == 1) {
                            driver.setAs(newDriver);
                            return true;
                        } else {
                            newDriver.getNextSlices();
                            if (pushSliceToSatisfied(newDriver, str.substring(1))) {
                                driver.setAs(newDriver);
                                return true;
                            }
                        }
                    } else if (remainStr.equals(str.substring(1))) {
                        driver.setAs(newDriver);
                        return true;
                    } else if (str.length() > 1 + remainStr.length()
                            && str.substring(1, 1 + remainStr.length()) == remainStr) {
                        newDriver.getNextSlices();
                        if (str.substring(1).startsWith(remainStr)
                                && pushSliceToSatisfied(newDriver, str.substring(1 + remainStr.length()))) {
                            driver.setAs(newDriver);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private DirectedEngine getLoopEngine(boolean exclude) {
            DirectedEngine loopEngine = new DirectedEngine();
            MatchGenerator loop = loopEngine.buildGenerators(path_end, loopEngine.headGenerator, false, null);
            loopEngine.directedPath.add(path_end);
            loopEngine.index = 1;
            if (exclude)
                loop.max = loop.min;
            else
                loop.min = loop.min + 1;
            loop.addMendatoryCase(null, loopEngine.headGenerator);
            loopEngine.finalGenerator = loop;
            return loopEngine;
        }

        private DirectedEngine getBranchEngine(boolean exclude) {
            DirectedEngine branchEngine = new DirectedEngine();
            Node newBranch = ((Branch) path_end).getNewBranch();
            if (exclude) {
                List<Node> tmp = new ArrayList<Node>();
                for (Node a : newBranch.new_atoms) {
                    if (a != curAtom)
                        tmp.add(a);
                }
                newBranch.new_atoms = tmp.toArray(new Node[tmp.size()]);
            } else
                newBranch.new_atoms = new Node[]{curAtom};
            MatchGenerator branch = branchEngine.buildGenerators(newBranch, branchEngine.headGenerator, false,
                    newBranch.direct_next);
            branchEngine.directedPath.add(newBranch);
            branchEngine.index = 1;
            branch.addMendatoryCase(null, branchEngine.headGenerator);
            branchEngine.finalGenerator = branch;
            return branchEngine;
        }

        private Set<DirectedEngine> getEngineSet() {
            Set<DirectedEngine> engineSet = new HashSet<DirectedEngine>();
            for (ArrayList<Node> tmpPath : pathSharing) {
                ArrayList<Node> pathCopy = new ArrayList<Node>(tmpPath);
                engineSet.add(new DirectedEngine(pathCopy, false));
            }

            if (type == VulType.BRANCH_IN_LOOP && path_end.self == "|") {
                DirectedEngine prefixEngine = null;
                DirectedEngine firstChoiceEngine = null;
                DirectedEngine secondChoiceEngine = null;
                DirectedEngine suffixEngine = null;

                for (Iterator<DirectedEngine> i = engineSet.iterator(); i.hasNext(); ) {
                    DirectedEngine engine = i.next();
                    if (path_end.direct_next == engine.directedPath.get(0)) {
                        suffixEngine = engine;
                        i.remove();
                    } else {
                        prefixEngine = engine;
                        i.remove();
                    }
                }

                firstChoiceEngine = getBranchEngine(true);
                secondChoiceEngine = getBranchEngine(false);
                engineSet.add(firstChoiceEngine);
                engineSet.add(secondChoiceEngine);

                if (suffixEngine != null) {
                    firstChoiceEngine.addFromEnginePath(suffixEngine);
                    secondChoiceEngine.addFromEnginePath(suffixEngine);
                }

                if (prefixEngine != null) {
                    ArrayList<Node> newList = new ArrayList<Node>(prefixEngine.directedPath);
                    DirectedEngine prefixEngineCopy = new DirectedEngine(newList);
                    prefixEngine.buildToEnd();
                    prefixEngine.addFromEngine(firstChoiceEngine);
                    prefixEngineCopy.addFromEngine(secondChoiceEngine);
                    engineSet.clear();
                    engineSet.add(prefixEngine);
                    engineSet.add(prefixEngineCopy);
                }
            } else if (type == VulType.LOOP_IN_LOOP || (type == VulType.BRANCH_IN_LOOP && path_end.self == "?")) {
                DirectedEngine prefixEngine = null;
                DirectedEngine suffixEngine = null;
                for (Iterator<DirectedEngine> i = engineSet.iterator(); i.hasNext(); ) {
                    DirectedEngine engine = i.next();
                    i.remove();
                    if (path_end.sub_next == engine.directedPath.get(0) || (path_end.new_atoms != null
                            && Arrays.asList(path_end.new_atoms).contains(engine.directedPath.get(0))))
                        continue;
                    else if (path_end.direct_next == engine.directedPath.get(0))
                        suffixEngine = engine;
                    else
                        prefixEngine = engine;
                }

                DirectedEngine excludeLoopEngine = getLoopEngine(true);
                DirectedEngine forceLoopEngine = getLoopEngine(false);
                engineSet.add(excludeLoopEngine);
                engineSet.add(forceLoopEngine);

                if (suffixEngine == null && path_end.direct_next != null) {
                    suffixEngine = new DirectedEngine();
                    suffixEngine.directedPath.addAll(getDirectPath(path_end.direct_next));
                }
                if (suffixEngine != null) {
                    excludeLoopEngine.addFromEnginePath(suffixEngine);
                    forceLoopEngine.addFromEnginePath(suffixEngine);
                }

                if (prefixEngine != null) {
                    ArrayList<Node> newList = new ArrayList<Node>(prefixEngine.directedPath);
                    DirectedEngine prefixEngineCopy = new DirectedEngine(newList);
                    prefixEngine.buildToEnd();
                    prefixEngine.addFromEngine(excludeLoopEngine);
                    prefixEngineCopy.addFromEngine(forceLoopEngine);
                    engineSet.clear();
                    engineSet.add(prefixEngine);
                    engineSet.add(prefixEngineCopy);
                }
            }

            return engineSet;
        }

        private String getPump() {
            Set<DirectedEngine> engineSet = getEngineSet();

            Set<Driver> driverSet = new HashSet<Driver>();
            for (DirectedEngine engine : engineSet) {
                Driver mainDriver = new Driver(engine);
                mainDriver.getNextSlices();
                if (mainDriver.nextSlices == null)
                    return null;
                driverSet.add(mainDriver);
            }

            ArrayList<Set<Driver>> setOfOptions = new ArrayList<Set<Driver>>();
            setOfOptions.add(driverSet);
            int size = 1;

            String result = null;

            for (int i = 0; i < size; i++) {
                Set<Driver> option = setOfOptions.get(i);
                if (option.size() == 0)
                    continue;
                if (option.iterator().next().matchingPath.length() > 9)
                    continue;

                if (allSatisfied(option)) {
                    StringBuffer pathString = option.iterator().next().matchingPath;
                    if (pathString.length() > 0) {
                        return pathString.toString();
                    }
                }

                // add all next possibilities for each driver
                Set<Integer> nextChar = null;
                // their intersection
                for (Driver driver : option) {
                    driver.getNextSlices();
                    if (driver.nextSlices == null) {
                        nextChar = null;
                        break;
                    }
                    driver.getNextCharSet();
                    if (driver.nextCharSetFull.size() == 0) {
                        nextChar = null;
                        break;
                    }
                    if (nextChar == null) {
                        nextChar = new HashSet<Integer>();
                        nextChar.addAll(driver.nextCharSetFull);
                    } else
                        nextChar.retainAll(driver.nextCharSetFull);
                }
                if (nextChar != null && nextChar.size() > 0) {
                    // get possible push options (remove non valid option)
                    Set<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>> lastOptions = null;
                    for (Driver driver : option) {
                        for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextCharSetMap.keySet()) {
                            driver.nextCharSetMap.get(triplet).retainAll(nextChar);
                            if (driver.nextCharSetMap.get(triplet).size() == 0)
                                driver.nextSlices.remove(triplet);
                        }
                        if (lastOptions == null) {
                            lastOptions = new HashSet<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>>();
                            for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextSlices) {
                                if (driver.nextCharSetMap.get(triplet) == null)
                                    continue;
                                Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> newMap = new HashMap<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>();
                                newMap.put(driver, triplet.addAt3(driver.nextCharSetMap.get(triplet)));
                                lastOptions.add(newMap);
                            }
                        } else {
                            Set<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>> newOptions = new HashSet<Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>>();
                            for (Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> lastMap : lastOptions) {
                                for (Triplet<Driver, Node, MatchGenerator> triplet : driver.nextSlices) {
                                    if (driver.nextCharSetMap.get(triplet) == null)
                                        continue;
                                    Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> newMap = new HashMap<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>>();
                                    newMap.putAll(lastMap);
                                    newMap.put(driver, triplet.addAt3(driver.nextCharSetMap.get(triplet)));
                                    newOptions.add(newMap);
                                }
                            }
                            lastOptions = newOptions;
                        }
                    }

                    for (Map<Driver, Quartet<Driver, Node, MatchGenerator, Set<Integer>>> optionMap : lastOptions) {
                        Set<Integer> charSet = null;
                        for (Driver driver : optionMap.keySet()) {
                            if (charSet == null) {
                                charSet = new HashSet<Integer>();
                                charSet.addAll(optionMap.get(driver).getValue3());
                            } else
                                charSet.retainAll(optionMap.get(driver).getValue3());
                            if (charSet.size() == 0)
                                break;
                        }
                        if (charSet.size() == 0)
                            continue;
                        else {
                            Set<Driver> newOption = getNewOption(optionMap, charSet.iterator().next());
                            if (newOption != null) {
                                setOfOptions.add(newOption);
                                size += 1;
                            }
                        }
                    }
                }
            }

            return result;
        }

        private String getSuffix() {
            ArrayList<Node> suffixPath = new ArrayList<Node>();
            Node p = suffixHead;
            while (p != null) {
                suffixPath.add(p);
                p = p.direct_next;
            }

            String suffix = "";
            try {
                DirectedEngine newEngine = new DirectedEngine(suffixPath, true);
                suffixDriver = new Driver(newEngine);
                suffix = suffixDriver.getShortestFailedMatch();
            } catch (Exception e) {
//                System.out.print(regex + "\n");
                e.printStackTrace();
            }
            return suffix;
        }

        public void checkPathSharing() {
            if (pathSharing.size() == 0 && (type != VulType.BRANCH_IN_LOOP || path_end.self == "?"))
                result = Existance.NOT_EXIST;
            else {
                String pumpStr = null;
                if (pathSharing.size() == 1 && (type != VulType.BRANCH_IN_LOOP || path_end.self == "?"))
                    pumpStr = getShortestMatching(pathSharing.get(0));
                else
                    pumpStr = getPump();
                if (pumpStr != null && pumpStr.length() > 0) {
                    pump.append(pumpStr);
                    prefix.append(getPrefix());
                    suffix.append(getSuffix());
                    result = Existance.EXIST;
                }
            }
        }

        private String getShortestMatching(ArrayList<Node> tmpPath) {
            String matching = "";
            try {
                DirectedEngine newEngine = new DirectedEngine(tmpPath);
                matching = newEngine.getShortestMatching();
            } catch (Exception e) {
                System.out.print(regex + "\n");
                e.printStackTrace();
            }
            return matching;
        }

        public void addPath(ArrayList<Node> tmpPath, boolean hide) {
            if (hide) {
                for (int i = 0; i < tmpPath.size(); i++) {
                    Node node = tmpPath.get(i);
                    Node next_node = null;
                    if (i < tmpPath.size() - 1)
                        next_node = tmpPath.get(i + 1);
                    else if (tmpPath == path)
                        next_node = path_end;
                    if (next_node != null && node.sub_next == next_node)
                        continue;
                    if (next_node != null && node.new_atoms != null
                            && Arrays.asList(node.new_atoms).contains(next_node))
                        continue;
                    if (pattern.checkSlice(node, false)) {
                        pathSharing.add(tmpPath);
                        break;
                    }
                }
            } else
                pathSharing.add(tmpPath);
        }

        public void printResult(BufferedWriter outVul, int index) throws IOException {
            String complexType = "";
            switch (type) {
                case LOOP_IN_LOOP:
                case BRANCH_IN_LOOP:
                    complexType = "Exponential";
                    break;
                case LOOP_AFTER_LOOP:
                    complexType = "Polynomial";
                    break;
            }
            if (result != Existance.NOT_EXIST) {
                if (!possible_vulnerability) {
                    outVul.write(regex + "\n");
                    possible_vulnerability = true;
                }
                if (result == Existance.EXIST)
                    printVul(outVul, index, prefix.toString(), pump.toString(), suffix.toString(), complexType);
                else
                    printSharingPath(pathSharing, complexType, outVul);
            }
        }

        private void initialize() {
            prefix = new StringBuffer();
            pump = new StringBuffer();
            suffix = new StringBuffer();
            pathSharing = new ArrayList<ArrayList<Node>>();
            fullPath = new ArrayList<Node>();
        }
    }

    public enum Existance {
        EXIST, NOT_EXIST, NOT_SURE
    }

    public Analyzer(Pattern regexPattern, int max_length) {
        pattern = regexPattern;
        maxLength = max_length;
        initialize();
        buildTree(pattern.root);
        removeInvalidLoop();
    }

    public enum VulType {
        LOOP_IN_LOOP, BRANCH_IN_LOOP, LOOP_AFTER_LOOP, DIY
    }

    public enum VulTypeDIY {
        OneCounting, POA, SLQ
    }

    public enum CurState {
        SATISFIED, UNSATISFIED, ONLEAVE
    }

    public void doDynamicAnalysis(BufferedWriter outVul, int index, double threshold) throws IOException {
        possibleVuls = new ArrayList<VulStructure>();

//        ArrayList<Node> tpath = new ArrayList<Node>(getDirectPath(this.pattern.root));
//        VulStructure tVul = new VulStructure(tpath, VulType.BRANCH_IN_LOOP);
//        tVul.pathSharing.add(getDirectPath(this.pattern.root.direct_next.direct_next.sub_next));
//        System.out.print(tVul.getPump()+"\n");
//        System.out.print(tVul.getShortestMatching(getDirectPath(this.pattern.root))+"\n");

        ArrayList<Node> tpath = new ArrayList<Node>(getDirectPath(this.pattern.root.direct_next.direct_next.sub_next));
        VulStructure tVul = new VulStructure(tpath, VulType.BRANCH_IN_LOOP);
        tVul.pathSharing.add(getDirectPath(this.pattern.root.direct_next.direct_next.sub_next));
        System.out.print(tVul.getPump() + "\n");
        System.out.print(tVul.getShortestMatching(getDirectPath(this.pattern.root)) + "\n");

//        for(ArrayList<Node> path : diyPaths){
//            VulStructure tVul = new VulStructure(path, VulType.LOOP_IN_LOOP);
//            tVul.checkPathSharing();
//            System.out.print(tVul.getPump());
//            System.out.print("\n");
//        }


        for (ArrayList<Node> path : loopInLoop) {
            VulStructure newVul = new VulStructure(path, VulType.LOOP_IN_LOOP);
            possibleVuls.add(newVul);
        }

        for (ArrayList<Node> path : branchInLoop) {
            Node pathEnd = path.get(path.size() - 1);
            if (pathEnd.self == "?") {
                VulStructure newVul = new VulStructure(path, VulType.BRANCH_IN_LOOP);
                newVul.fullPath.addAll(getDirectPath(pathEnd.new_atoms[0]));
                newVul.fullPath.addAll(getDirectPath(pathEnd.direct_next));
                newVul.addPath(getDirectPath(pathEnd.new_atoms[0]), false);
                possibleVuls.add(newVul);
            } else {
                for (Node atom : pathEnd.new_atoms) {
                    ArrayList<Node> tmpPath = new ArrayList<Node>();
                    tmpPath.addAll(path);
                    VulStructure newVul = new VulStructure(tmpPath, VulType.BRANCH_IN_LOOP);
                    newVul.curAtom = atom;
                    possibleVuls.add(newVul);
                    if (pathEnd.new_atoms.length == 2)
                        break;
                }
            }
        }

        for (ArrayList<Node> path : loopAfterLoop) {
            VulStructure newVul = new VulStructure(path, VulType.LOOP_AFTER_LOOP);
            possibleVuls.add(newVul);
        }

        for (VulStructure vulCase : possibleVuls) {
            vulCase.checkPathSharing();
            if (vulCase.result == Existance.EXIST) {
                if (checkResult(vulCase.prefix.toString(), vulCase.pump.toString(), vulCase.suffix.toString(),
                        maxLength, threshold)) {
                    vulCase.printResult(outVul, index);
                    break;
                }
                vulCase.suffixDriver.traverseToLast();
                String previousPath = vulCase.suffixDriver.matchingPath.toString();
                if (previousPath.length() > 1)
                    previousPath = previousPath.substring(0, 1);
                else if (previousPath.length() == 0 && vulCase.suffixDriver.curGenerator.curNode.direct_next != null) {
                    Set<Integer> nextMatchSet = pattern
                            .getFirstMatchSet(vulCase.suffixDriver.curGenerator.curNode.direct_next);
                    if (nextMatchSet != null && nextMatchSet.size() > 0)
                        previousPath = PatternUtils.convertString(nextMatchSet.iterator().next());
                }
                vulCase.suffixDriver.matchingPath.setLength(0);
                String lastFailedStr = vulCase.suffixDriver.getShortestFailedMatch();
                if (lastFailedStr == "")
                    lastFailedStr = previousPath;
                if (checkResult(vulCase.prefix.toString(), vulCase.pump.toString(),
                        vulCase.suffix.toString() + lastFailedStr, maxLength, threshold)) {
                    vulCase.suffix.append(lastFailedStr);
                    vulCase.printResult(outVul, index);
                    break;
                }
                if (lastFailedStr != previousPath && previousPath != "" && checkResult(vulCase.prefix.toString(),
                        vulCase.pump.toString(), vulCase.suffix.toString() + previousPath, maxLength, threshold)) {
                    vulCase.suffix.setLength(vulCase.suffix.length() - lastFailedStr.length());
                    vulCase.suffix.append(previousPath);
                    vulCase.printResult(outVul, index);
                    break;
                }
            }
        }
    }

    private boolean checkResult(String prefix, String pump, String suffix, int maxLength, double threshold) {
        double matchingStepCnt = 0;
        matchingStepCnt = pattern.getMatchingStepCnt(prefix, pump, suffix, maxLength, threshold);
        if (matchingStepCnt >= threshold)
            return true;
        return false;
    }

    private boolean onDirectNext(Node pA, Node pB) {
        Node a = pA.direct_next;
        Node b = pB;
        if (a == null)
            return false;
        while (a != b && a.direct_next != null && a.sub_next == null && !(a instanceof Branch)) {
            if (pattern.isSlice(a))
                return false;
            a = a.direct_next;
        }
        return a == b;
    }

    public void doStaticAnalysisDIY() {
        possibleVuls = new ArrayList<VulStructure>();
        // 将所有循环节点能够到达的路径放入allMatchs
        for (Node node : loopNodes) {
            ArrayList<ArrayList<Set<Integer>>> tmp = getAllMatchSets(node, node.direct_next, new ArrayList<>(), 4);
            tmp.removeIf(t -> t.size() == 0);
            allMatchs.add(tmp);
//            VulStructure vul = new VulStructure(node, tmp);
//            possibleVuls.add(vul);


            Set<ArrayList<Set<Integer>>> possiblePath = new HashSet<>();

            // 检查自己生成的路径中有没有重叠（EOA、EOD、NQ）
            for (int i = 0; i < tmp.size() - 1; i++) {
                for (int j = i + 1; j < tmp.size(); j++) {
                    overlap o = checkOverlap(tmp.get(i), tmp.get(j));
                    if (o.type != 0 && !possiblePath.contains(o.bigOne)) {
                        possiblePath.add(o.bigOne);
                    }
                }
            }

            for (ArrayList<Set<Integer>> p : possiblePath) {
                VulStructure vul = new VulStructure(node, p, VulTypeDIY.OneCounting);
                possibleVuls.add(vul);
            }
        }

//        for (ArrayList<ArrayList<Set<Integer>>> paths : allMatchs) {
//            // 对每个loopNode所导出的所有路径，两两之间进行比较
//            ArrayList<overlap> tmp = new ArrayList<>();
//            for (int i = 0; i < paths.size() - 1; i++) {
//                for (int j = i + 1; j < paths.size(); j++) {
//                    overlap o = checkOverlap(paths.get(i), paths.get(j));
//                    if (o.type != 0) tmp.add(o);
//                }
//            }
//            if (tmp.size() > 0) {
//                overlaps.add(tmp);
//            }
//        }

        // 检查三条路径之间的关系（POA）
//        // 1. 两条路径直接相连
//        ArrayList<Node> loopNodeList = new ArrayList<Node>(loopNodes);
//        for (int i = 0; i < loopNodeList.size() - 1; i++) {
//            for (int j = i + 1; j < loopNodeList.size(); j++) {
//                Node a = loopNodeList.get(i);
//                Node b = loopNodeList.get(j);
//                Node pA = pattern.getDirectParent(a);
//                Node pB = pattern.getDirectParent(b);
////                if (onDirectNext(pA, pB) || pA.self == "|" && pA == pB) {
//                if (onDirectNext(pA, pB)) {
//                    ArrayList<Node> nPath = new ArrayList<Node>();
//                    nPath.add(a);
//                    nPath.add(b);
//                    loopAfterLoop.add(nPath);
//                } else if (onDirectNext(pB, pA)) {
//                    ArrayList<Node> nPath = new ArrayList<Node>();
//                    nPath.add(b);
//                    nPath.add(a);
//                    loopAfterLoop.add(nPath);
//                }
//            }
//        }
        // 2.两条路径中间相隔
        ArrayList<Node> loopNodeList = new ArrayList<Node>(loopNodes);
        for (int i = 0; i < loopNodeList.size() - 1; i++) {
            for (int j = i + 1; j < loopNodeList.size(); j++) {
                Node a = loopNodeList.get(i);
                Node b = loopNodeList.get(j);

                Node a2GetDirectNext=a;while(a2GetDirectNext.direct_next==null)a2GetDirectNext=a2GetDirectNext.direct_prev;
                Node b2GetDirectNext=b;while(b2GetDirectNext.direct_next==null)b2GetDirectNext=b2GetDirectNext.direct_prev;


                ArrayList<ArrayList<Set<Integer>>> aPaths = allMatchs.get(i);
                ArrayList<ArrayList<Set<Integer>>> bPaths = allMatchs.get(j);

                // p1、p3?
                for (ArrayList<Set<Integer>> aPath : aPaths) {
                    for (ArrayList<Set<Integer>> bPath : bPaths) {


                        // 判断两条路径是否相等
                        overlap o = checkOverlap(aPath, bPath);
                        if (o.type == 3) {
                            // 求中间串p2, order为0则a为p1、b为p3，order为1则b为p1、a为p3
                            meetEnd = false;
                            int order = 0;
                            ArrayList<ArrayList<Set<Integer>>> p2 = getAllMatchSets(a2GetDirectNext.direct_next, b, new ArrayList<>(), 1000);
                            if (meetEnd == false) {
                                p2 = getAllMatchSets(b2GetDirectNext.direct_next, a, new ArrayList<>(), 1000);
                                order = 1;
                            }

                            // 按理说无论如何都不可能两个counting之间不存在先后关系，这里只是以防万一
                            if (meetEnd == false) {
                                System.out.println("Never meet the End");
                                continue;
                            }

                            p2.removeIf(t -> t.size() == 0);
                            // 两串路径直接相接，则跳过
                            if (p2.size() == 0) {
                                continue;
                            }

                            // order为0则a为p1、b为p3，order为1则b为p1、a为p3
                            if (order == 0) {
                                for(ArrayList<Set<Integer>> t : p2){
                                    // p2是p1后缀
                                    overlap mid1 = checkOverlap(aPath, t);
                                    if(mid1.type==2&&mid1.bigOne==aPath){
                                        VulStructure vul = new VulStructure(a, b, mid1.suffix, VulTypeDIY.POA);
                                        possibleVuls.add(vul);
                                    }
                                    // p2是p3前缀
                                    overlap mid2 = checkOverlap(bPath, t);
                                    if(mid1.type==1&&mid1.bigOne==bPath){
                                        VulStructure vul = new VulStructure(a, b, mid2.preffix, VulTypeDIY.POA);
                                        possibleVuls.add(vul);
                                    }
                                }
                            } else {
                                for(ArrayList<Set<Integer>> t : p2){
                                    // p2是p1后缀
                                    overlap mid1 = checkOverlap(bPath, t);
                                    if(mid1.type==2&&mid1.bigOne==bPath){
                                        VulStructure vul = new VulStructure(a, b, mid1.suffix, VulTypeDIY.POA);
                                        possibleVuls.add(vul);
                                    }
                                    // p2是p3前缀
                                    overlap mid2 = checkOverlap(aPath, t);
                                    if(mid1.type==1&&mid1.bigOne==aPath){
                                        VulStructure vul = new VulStructure(b, a, mid2.preffix, VulTypeDIY.POA);
                                        possibleVuls.add(vul);
                                    }
                                }
                            }
                        }
//                        // 判断两条路径是否相等
//                        if (aPath.size() == bPath.size()) {
//                            boolean equal = true;
//                            ArrayList<Set<Integer>> tmpPath = new ArrayList<>();
//                            for (int k = 0; k < aPath.size(); k++) {
//                                Set<Integer> tmpSet = new HashSet<>();
//                                tmpSet.addAll(aPath.get(k));
//                                tmpSet.retainAll(bPath.get(k));
//                                if (tmpSet.size() == 0) {
//                                    equal = false;
//                                    break;
//                                } else {
//                                    tmpPath.add(tmpSet);
//                                }
//                            }
//                            // 两条路径确实相等
//                            if (equal && tmpPath.size() == aPath.size()) {
//                                // 求中间串p2
//                                meetEnd = false;
//                                ArrayList<ArrayList<Set<Integer>>> tmp = getAllMatchSets(a, b, new ArrayList<>(), 4);
//                                if (meetEnd == false) {
//                                    tmp = getAllMatchSets(b, a, new ArrayList<>(), 4);
//                                }
//                                // 按理说无论如何都不可能两个counting之间不存在先后关系，这里只是以防万一
//                                if(meetEnd==false){
//                                    System.out.println("Never meet the End");
//                                    continue;
//                                }
//                                tmp.removeIf(t -> t.size() == 0);
//                                // 两串路径直接相接，则跳过
//                                if(tmp.size()==0){
//                                    continue;
//                                }
//                                overlap o = checkOverlap(tmp.get(i), tmp.get(j));
//                                if (o.type != 0 && !possiblePath.contains(o.bigOne)) {
//                                    possiblePath.add(o.bigOne);
//                                }
//                            }
//                        }
                    }
                }

            }
        }
//        System.out.print("");
    }

    public void doStaticAnalysis() {
        ArrayList<Node> loopNodeList = new ArrayList<Node>(loopNodes);
        for (int i = 0; i < loopNodeList.size() - 1; i++) {
            for (int j = i + 1; j < loopNodeList.size(); j++) {
                Node a = loopNodeList.get(i);
                Node b = loopNodeList.get(j);
                Node pA = pattern.getDirectParent(a);
                Node pB = pattern.getDirectParent(b);
//                if (onDirectNext(pA, pB) || pA.self == "|" && pA == pB) {
                if (onDirectNext(pA, pB)) {
                    ArrayList<Node> nPath = new ArrayList<Node>();
                    nPath.add(a);
                    nPath.add(b);
                    loopAfterLoop.add(nPath);
                } else if (onDirectNext(pB, pA)) {
                    ArrayList<Node> nPath = new ArrayList<Node>();
                    nPath.add(b);
                    nPath.add(a);
                    loopAfterLoop.add(nPath);
                }
            }
        }

//        // 将所有Loop节点的路径存入diyPath
//        for (Node node : loopNodes) {
//            ArrayList<Node> tmp = new ArrayList<Node>();
//            tmp.addAll(getPath(node.sub_next, new ArrayList<Node>()));
//            diyPaths.add(tmp);
//            System.out.print(tmp+"\n");
//        }
//
//        for(ArrayList<Node> path : diyPaths){
//            ArrayList<Set<Integer>>tmp = new ArrayList<>();
//            for(Node node : path){
//                if (pattern.isCharSet(node))
////                    System.out.print(pattern.getFullMatchSet(node));
//                    tmp.add(pattern.getFullMatchSet(node));
//                else
////                    System.out.print(pattern.getFullMatchList(node));
//                    for(Integer i : pattern.getFullMatchList(node)){
//                        Set<Integer> t = new HashSet<Integer>();
//                        t.add(i);
//                        tmp.add(t);
////                        System.out.print(i+"\t"+tmp+"\n");
//                    }
//            }
//            diyMatchs.add(tmp);
////            System.out.print("\n");
//        }
//
//        System.out.print("here:\n");
//        for(int i = 0; i < diyMatchs.size() - 1; i++){
//            for(int j = i + 1; j < diyMatchs.size(); j++){
//                int tmp = -1;
//                if(diyMatchs.get(i).size() < diyMatchs.get(j).size())
////                    tmp = judgeTwoPath(diyPaths.get(i), diyPaths.get(j));
//                    tmp = judgeTwo(diyMatchs.get(i), diyMatchs.get(j));
//                else
////                    tmp = judgeTwoPath(diyPaths.get(j),diyPaths.get(i));
//                    tmp = judgeTwo(diyMatchs.get(j),diyMatchs.get(i));
//                System.out.print(diyMatchs.get(i)+"\n");
//                System.out.print(diyMatchs.get(j)+"\n");
//                System.out.print(tmp+"\n\n");
//            }
//        }

        // 将所有循环节点能够到达的路径放入allMatchs
        for (Node node : loopNodes) {
//            allMatchs.add(getAllFullMatchSets(i, node, node.direct_next, new ArrayList<Set<Integer>>(), 0, 4));
            ArrayList<ArrayList<Set<Integer>>> tmp = getAllMatchSets(node, node.direct_next, new ArrayList<>(), 4);
//            for(int i = 0; i < tmp.size(); i++){
//                if(tmp.get(i).size()==0)tmp.remove(i);
//            }
            tmp.removeIf(t -> t.size() == 0);
            allMatchs.add(tmp);
        }

        for (ArrayList<ArrayList<Set<Integer>>> paths : allMatchs) {
            // 对每个loopNode所导出的所有路径，两两之间进行比较
            ArrayList<overlap> tmp = new ArrayList<>();
            for (int i = 0; i < paths.size() - 1; i++) {
                for (int j = i + 1; j < paths.size(); j++) {
                    overlap o = checkOverlap(paths.get(i), paths.get(j));
                    if (o.type != 0) tmp.add(o);
                }
            }
            if (tmp.size() > 0) overlaps.add(tmp);
        }

        for (Node node : loopNodes) {
            ArrayList<Node> path = new ArrayList<Node>();
            path.add(node);
            if (node.direct_next != null)
                getPathFromLoop(node.direct_next, path, true);
            if (node.sub_next != null)
                getPathFromLoop(node.sub_next, path, false);
        }
    }

    private ArrayList<Node> getDirectPath(Node node) {
        ArrayList<Node> path = new ArrayList<Node>();
        while (node != null) {
            path.add(node);
            node = node.direct_next;
        }
        return path;
    }

    private void printVul(BufferedWriter outVul, int index, String prefix, String pump, String suffix, String vulType)
            throws IOException {
        outVul.write("Find vulnerability (" + vulType + ") in structure!\n");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("regex", regex);
        jsonObject.put("prefix", prefix);
        jsonObject.put("pump", pump);
        jsonObject.put("suffix", suffix);
        if (index != -1)
            jsonObject.put("index", index);
        outVul.write(jsonObject + "\n");
    }

    private void printSharingPath(ArrayList<ArrayList<Node>> pathSharing, String complexity_type, BufferedWriter outVul)
            throws IOException {
        outVul.write(complexity_type + " complexity exist if these path below share same subexpression: \n");
        for (int i = 0; i < pathSharing.size(); i++)
            outVul.write(String.format("  p%d: ", i + 1) + getPathString(pathSharing.get(i)) + "\n");
    }

    private String getPathString(ArrayList<Node> path) {
        String str = new String();
        for (Node node : path) {
            if (node != null) {
                str += node.self;
                str += "->";
            }
        }
        return str;
    }

    private ArrayList<ArrayList<Node>> getCombination(Node[] atoms, int count) {
        ArrayList<ArrayList<Node>> combination = new ArrayList<ArrayList<Node>>();
        int atom_length = atoms.length;
        if (atom_length < count)
            return combination;

        boolean flag = false;

        int[] tempNum = new int[atom_length];
        for (int i = 0; i < atom_length; i++) {
            if (i < count)
                tempNum[i] = 1;
            else
                tempNum[i] = 0;
        }

        do {
            combination.add(createCombinationResult(atoms, tempNum, count));
            flag = false;
            for (int i = atom_length - count; i < atom_length; i++)
                if (tempNum[i] == 0)
                    flag = true;

            int pose = 0;
            int sum = 0;
            for (int i = 0; i < (atom_length - 1); i++) {
                if (tempNum[i] == 1 && tempNum[i + 1] == 0) {
                    tempNum[i] = 0;
                    tempNum[i + 1] = 1;
                    pose = i;
                    break;
                }
            }

            for (int i = 0; i < pose; i++)
                if (tempNum[i] == 1)
                    sum++;

            for (int i = 0; i < pose; i++) {
                if (i < sum)
                    tempNum[i] = 1;
                else
                    tempNum[i] = 0;
            }
        } while (flag);
        return combination;
    }

    private ArrayList<Node> createCombinationResult(Node[] a, int[] temp, int m) {
        ArrayList<Node> result = new ArrayList<Node>();
        for (int i = 0; i < a.length; i++)
            if (temp[i] == 1)
                result.add(a[i]);
        return result;
    }

    public boolean isVulnerable() {
        return possible_vulnerability;
    }

    // 输入一个节点，输出其内所包含的路径
    private ArrayList<Node> getPath(Node node, ArrayList<Node> prev_path) {
        if (node == null) {
            return prev_path;
        }
        ArrayList<Node> curr_path = new ArrayList<Node>();
        curr_path.addAll(prev_path);
        curr_path.add(node);
        if (node.sub_next != null)
            curr_path.addAll(getPath(node.sub_next, new ArrayList<Node>()));
        curr_path.addAll(getPath(node.direct_next, new ArrayList<Node>()));
        return curr_path;
    }

    public boolean equalNode(Node node1, Node node2) {
        return true;
    }

    public int judgeTwo(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2) {
        boolean front = true;
        boolean back = true;
        for (int i = 0; i < path1.size(); i++) {
            Set<Integer> result = new HashSet<Integer>();
            result.addAll(path1.get(i));
            result.retainAll(path2.get(i));
            if (result.size() == 0) {
                front = false;
                break;
            }
        }
        int c = path2.size() - path1.size();
        for (int i = path1.size() - 1; i >= 0; i--) {
            Set<Integer> result = new HashSet<Integer>();
            result.addAll(path1.get(i));
            result.retainAll(path2.get(i + c));
            if (result.size() == 0) {
                back = false;
                break;
            }
        }
        if (front && back)
            return 3;
        else if (front)
            return 1;
        else if (back)
            return 2;
        else
            return 0;
    }

    // 输入两个节点，输出两者是否存在前缀包含、后缀包含、完全包含，默认path1短于path2
    public int judgeTwoPath(ArrayList<Node> path1, ArrayList<Node> path2) {
        int status;
        boolean front = true;
        boolean back = true;
        for (int i = 0; i < path1.size(); i++) {
            if (path1.get(i) != path2.get(i)) {
                front = false;
                break;
            }
        }
        int c = path2.size() - path1.size();
        for (int i = path1.size() - 1; i >= 0; i--) {
            if (path1.get(i) != path2.get(i + c)) {
                back = false;
                break;
            }
        }
        if (front && back)
            return 3;
        else if (front)
            return 1;
        else if (back)
            return 2;
        else
            return 0;
    }

    private class overlap {
        int type;
        ArrayList<Set<Integer>> bigOne;
        ArrayList<Set<Integer>> smallOne;
        ArrayList<Set<Integer>> preffix;
        ArrayList<Set<Integer>> suffix;

        public overlap() {
            type = 0;
            bigOne = new ArrayList<Set<Integer>>();
            smallOne = new ArrayList<Set<Integer>>();
            preffix = new ArrayList<Set<Integer>>();
            suffix = new ArrayList<Set<Integer>>();
        }

//        public boolean isPreffixOverlap(){
//            if(preffix.size()>0)return true;
//            return false;
//        }
//
//        public boolean isSuffixOverlap(){
//            if(suffix.size()>0)return true;
//            return false;
//        }
//
//        public boolean isCompleteOverlap(){
//            if (preffix.size()==suffix.size() && bigOne.size()==smallOne.size() && preffix.size() == bigOne.size()){
//                return true;
//            }
//            return false;
//        }
    }

    public overlap checkOverlap(ArrayList<Set<Integer>> path1, ArrayList<Set<Integer>> path2) {
//        for(ArrayList<ArrayList<Set<Integer>>> path : allMatchs)
//            // 对每个loopNode所导出的所有路径，两两之间进行比较
//            for(int i = 0; i < path.size() - 1; i++){
//                for(int j = i + 1; j < path.size(); j++){
//                    for (int k = 0; k < path.get(i).size()&&k < path.get(j).size();k++) {
//                        // 比较两个路径每个节点的重合
//                        // 如果两个Set都为空，则新建Set为空
//                        // 如果一个Set为空，另一个不为空，则新建Set为不空Set
//                        // 如果两个都不为空，先判断有没有交集，无交集则修改flag并退出，有交集则
//                    }
//                }
//            }

        overlap ans = new overlap();


        int n;
        if (path1.size() > path2.size()) {
            n = path2.size();
            ans.bigOne = path1;
            ans.smallOne = path2;
        } else {
            n = path1.size();
            ans.bigOne = path2;
            ans.smallOne = path1;
        }

        int flag = 0;
        for (int i = 0; i < n; i++) {
            // 比较两个路径每个节点的重合
            // 如果两个Set都为空，则新建Set为空
            // 如果一个Set为空，另一个不为空，则新建Set为不空Set
            // 如果两个都不为空，先判断有没有交集，无交集则修改flag并退出，有交集则
            Set<Integer> tmp;
            if (path1.get(i).contains(-1) && path2.get(i).contains(-1)) {
                tmp = new HashSet<Integer>();
                tmp.add(-1);
            } else if (path1.get(i).contains(-1)) {
                tmp = new HashSet<>(path2.get(i));
            } else if (path2.get(i).contains(-1)) {
                tmp = new HashSet<>(path1.get(i));
            } else {
                tmp = new HashSet<>(path1.get(i));
                tmp.retainAll(path2.get(i));
                if (tmp.size() == 0) {
                    flag = 1;
                    break;
                }
            }
            ans.preffix.add(tmp);
        }

        if (flag == 0) ans.type = 1;

        flag = 0;
        for (int i = 1; path1.size() - i >= 0 && path2.size() - i >= 0; i++) {
            // 比较两个路径每个节点的重合
            // 如果两个Set都为空，则新建Set为空
            // 如果一个Set为空，另一个不为空，则新建Set为不空Set
            // 如果两个都不为空，先判断有没有交集，无交集则修改flag并退出，有交集则
            Set<Integer> tmp;
            if (path1.get(path1.size() - i).contains(-1) && path2.get(path2.size() - i).contains(-1)) {
                tmp = new HashSet<>();
            } else if (path1.get(path1.size() - i).contains(-1)) {
                tmp = new HashSet<>(path2.get(path2.size() - i));
            } else if (path2.get(path2.size() - i).contains(-1)) {
                tmp = new HashSet<>(path1.get(path1.size() - i));
            } else {
                tmp = new HashSet<>(path1.get(path1.size() - i));
                tmp.retainAll(path2.get(path2.size() - i));
                if (tmp.size() == 0) {
                    flag = 1;
                    break;
                }
            }
            ans.suffix.add(0, tmp);
        }

        if (flag == 0) {
            if (ans.type == 1) ans.type = 3;
            else ans.type = 2;
        }

        // 完全无交集返回 0
        // 前缀返回 1
        // 后缀返回 2
        // 完全重合 3
        // 问题：是否在乎重合种类，以及要不要记录是哪两条路径重合
        return ans;
    }

    boolean meetEnd;

    public ArrayList<ArrayList<Set<Integer>>> getAllMatchSets(Node node, Node end, ArrayList<Set<Integer>> prevPath, int LL) {
        ArrayList<ArrayList<Set<Integer>>> paths = new ArrayList<ArrayList<Set<Integer>>>();
//        ArrayList<ArrayList<Set<Integer>>> fullPaths = new ArrayList<ArrayList<Set<Integer>>>();
        if (node instanceof Pattern.CharProperty || node instanceof Pattern.SliceNode || node instanceof Pattern.BnM) {
            ArrayList<Set<Integer>> path = new ArrayList<Set<Integer>>();
            if (pattern.isCharSet(node)) {
                // Dot的Set是空
                if (node instanceof Pattern.Dot) {
                    Set<Integer> tmp = new HashSet<Integer>();
                    tmp.add(-1);
                    path.add(tmp);

                } else {
                    Pattern.CharProperty charNode = (Pattern.CharProperty) node;
                    path.add(charNode.getCharSet());
                }
            } else {
                String str;
                if (node instanceof Pattern.SliceNode) str = ((Pattern.SliceNode) node).getSliceBuffer();
                else str = ((Pattern.BnM) node).getSliceBuffer();
//                if (str.length() == 0)
//                    return paths;
                assert str.length() > 0;
                for (String retval : str.split("")) {
//                    System.out.print((int)retval.charAt(0));
                    Set<Integer> char2Int = new HashSet<Integer>();
                    char2Int.add((int)retval.charAt(0));
                    path.add(char2Int);
                }
            }
            paths.add(path);
        } else if (node instanceof Branch) {
            for (Node atom : node.atoms) {
                // ?也是branch，atoms是null和元组里的内容，self是'?'
                if (atom != null) paths.addAll(getAllMatchSets(atom, end, new ArrayList<Set<Integer>>(), LL));
            }
        } else if (node instanceof Pattern.Loop) {
            ArrayList<ArrayList<Set<Integer>>> tmp_paths = new ArrayList<ArrayList<Set<Integer>>>();
            assert node.sub_next != null;
            tmp_paths = getAllMatchSets(node.sub_next, end, new ArrayList<Set<Integer>>(), LL);
            for (ArrayList<Set<Integer>> path : tmp_paths) {
                while (path.size() < ((Pattern.Loop) node).cmin) path.addAll(path);
                ArrayList<Set<Integer>> tmp_path = new ArrayList<>(path);
                if (((Pattern.Loop) node).cmax == Integer.MAX_VALUE || ((Pattern.Loop) node).cmax == 0) {
                    while (tmp_path.size() < LL) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                        if (path.size() == 0) break;
                    }
                } else {
                    while (tmp_path.size() < ((Pattern.Loop) node).cmax) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                    }
                }
            }
            if (((Pattern.Loop) node).cmin == 0) paths.add(new ArrayList<>());
        } else if (node instanceof Pattern.Curly) {
            ArrayList<ArrayList<Set<Integer>>> tmp_paths = new ArrayList<ArrayList<Set<Integer>>>();
            assert node.sub_next != null;
            tmp_paths = getAllMatchSets(node.sub_next, end, new ArrayList<Set<Integer>>(), LL);
            for (ArrayList<Set<Integer>> path : tmp_paths) {
                while (path.size() < ((Pattern.Curly) node).cmin) path.addAll(path);
                ArrayList<Set<Integer>> tmp_path = new ArrayList<>(path);
                if (((Pattern.Curly) node).cmax == Integer.MAX_VALUE || ((Pattern.Curly) node).cmax == 0) {
                    while (tmp_path.size() < LL) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                    }
                } else {
                    while (tmp_path.size() < ((Pattern.Curly) node).cmax) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                    }
                }
            }
            if (((Pattern.Curly) node).cmin == 0) paths.add(new ArrayList<>());
        } else if (node instanceof  Pattern.GroupCurly) {
            ArrayList<ArrayList<Set<Integer>>> tmp_paths = new ArrayList<ArrayList<Set<Integer>>>();
            assert node.sub_next != null;
            tmp_paths = getAllMatchSets(node.sub_next, end, new ArrayList<Set<Integer>>(), LL);
            for (ArrayList<Set<Integer>> path : tmp_paths) {
                while (path.size() < ((Pattern.GroupCurly) node).cmin) path.addAll(path);
                ArrayList<Set<Integer>> tmp_path = new ArrayList<>(path);
                if (((Pattern.GroupCurly) node).cmax == Integer.MAX_VALUE || ((Pattern.GroupCurly) node).cmax == 0) {
                    while (tmp_path.size() < LL) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                    }
                } else {
                    while (tmp_path.size() < ((Pattern.GroupCurly) node).cmax) {
                        paths.add(new ArrayList<>(tmp_path));
                        tmp_path.addAll(path);
                    }
                }
            }
            if (((Pattern.GroupCurly) node).cmin == 0) paths.add(new ArrayList<>());
        }

        assert node.direct_next != null;
        if (node.direct_next == end) {
            meetEnd = true;
            return paths;
        }

        ArrayList<ArrayList<Set<Integer>>> new_paths = new ArrayList<ArrayList<Set<Integer>>>();

        if (paths.size() > 0)
            for (ArrayList<Set<Integer>> path : paths) {
                if (path.size() + prevPath.size() > LL) continue;
                else {
                    ArrayList<Set<Integer>> tmp_path = new ArrayList<>(prevPath);
                    tmp_path.addAll(path);

                    if (node.direct_next != null)
                        new_paths.addAll(getAllMatchSets(node.direct_next, end, tmp_path, LL));
                    else new_paths.add(tmp_path);
                }
            }
        else if (node.direct_next != null)
            new_paths = getAllMatchSets(node.direct_next, end, prevPath, LL);
        else {
            new_paths.add(prevPath);
            return new_paths;
        }


        return new_paths;
    }

    public ArrayList<ArrayList<Set<Integer>>> getAllFullMatchSets(int i, Node node, Node end, ArrayList<Set<Integer>> prevPath, int count, int LL) {
        ArrayList<Set<Integer>> path = new ArrayList<Set<Integer>>();
        ArrayList<ArrayList<Set<Integer>>> paths = new ArrayList<ArrayList<Set<Integer>>>();
        ArrayList<ArrayList<Set<Integer>>> result = null;

        if (path.size() > LL) return null;

        if (node instanceof Branch) {
            for (Node atom : node.atoms) {
                result = getAllFullMatchSets(i, atom, end, path, 0, LL);
                if (result != null && result.size() > 0) paths.addAll(result);
            }
        } else if (node instanceof Pattern.Loop) {
            count++;
            // 反复添加自己
            result = getAllFullMatchSets(i, node, end, path, count, LL);
            if (result != null && result.size() > 0) paths.addAll(result);
//
//            for(ArrayList<Set<Integer>>r : result){
//
//            }
            if (((Pattern.Loop) node).cmax == Integer.MAX_VALUE || ((Pattern.Loop) node).cmax == 0) {
                result = getAllFullMatchSets(i, node, end, path, count, LL);
                if (result != null && result.size() > 0) paths.addAll(result);
            } else if (count < ((Pattern.Loop) node).cmax) {
                result = getAllFullMatchSets(i, node, end, path, count, LL);
                if (result != null && result.size() > 0) paths.addAll(result);
            }

            // 不添加自己，直接添加下一个
            if (path.size() > 0) paths.add(path);
        } else if (node instanceof Pattern.Curly) {
            count++;
            // 反复添加自己
            if (((Pattern.Curly) node).cmax == Integer.MAX_VALUE || ((Pattern.Curly) node).cmax == 0) {
                if (count < LL) {
                    result = getAllFullMatchSets(i, node, end, path, count, LL);
                    if (result != null && result.size() > 0) paths.addAll(result);
                }
            } else if (count < ((Pattern.Curly) node).cmax) {
                result = getAllFullMatchSets(i, node, end, path, count, LL);
                if (result != null && result.size() > 0) paths.addAll(result);
            }

            // 不添加自己，直接添加下一个
            if (path.size() > 0) paths.add(path);
        } else if (pattern.isCharSet(node) || node instanceof Pattern.SliceNode || node instanceof Pattern.BnM) {
            if (pattern.isCharSet(node)) {
                Pattern.CharProperty charNode = (Pattern.CharProperty) node;
                path.add(charNode.getCharSet());
            } else {
                String str;
                if (node instanceof Pattern.SliceNode) str = ((Pattern.SliceNode) node).getSliceBuffer();
                else str = ((Pattern.BnM) node).getSliceBuffer();
//                if (str.length() == 0)
//                    return paths;
                assert str.length() > 0;
                for (String retval : str.split("")) {
                    path.add(new HashSet<Integer>((int) retval.charAt(0)));
                }
            }
            paths.add(path);
        }


        ArrayList<ArrayList<Set<Integer>>> new_paths = new ArrayList<ArrayList<Set<Integer>>>();
        if (node.sub_next != null) {
            ArrayList<ArrayList<Set<Integer>>> sub_paths = new ArrayList<ArrayList<Set<Integer>>>();
            if (paths.size() > 0) {
                for (ArrayList<Set<Integer>> p : paths) {
                    result = getAllFullMatchSets(i, node.sub_next, end, p, 0, LL);
                    if (result != null && result.size() > 0) sub_paths.addAll(result);
                }
            } else {
                result = getAllFullMatchSets(i, node.sub_next, end, path, 0, LL);
                if (result != null && result.size() > 0) sub_paths.addAll(result);
            }
            if (sub_paths.size() > 0) {
                for (ArrayList<Set<Integer>> p : sub_paths) {
                    result = getAllFullMatchSets(i, node.direct_next, end, p, 0, LL);
                    if (result != null && result.size() > 0) new_paths.addAll(result);
                }
            } else {
                result = getAllFullMatchSets(i, node.direct_next, end, path, 0, LL);
                if (result != null && result.size() > 0) new_paths.addAll(result);
            }

        } else if (node.direct_next != null) {
            if (paths.size() > 0)
                for (ArrayList<Set<Integer>> p : paths) {
                    result = getAllFullMatchSets(i, node.direct_next, end, p, 0, LL);
                    if (result != null && result.size() > 0) new_paths.addAll(result);
                }
            else {
                result = getAllFullMatchSets(i, node.direct_next, end, path, 0, LL);
                if (result != null && result.size() > 0) new_paths.addAll(result);
            }
        } else {
            if (paths.size() == 0)
                paths.add(path);
            return paths;
        }

        return new_paths;
    }

    private void getPathFromLoop(Node node, ArrayList<Node> prev_path, boolean direct) {
        if (node == null)
            return;
        ArrayList<Node> curr_path = new ArrayList<Node>();
        curr_path.addAll(prev_path);
        curr_path.add(node);
        if (pattern.isBacktrackLoop(node)) {
            if (direct)
                loopAfterLoop.add(curr_path);
            else if (!pattern.isCertainCntLoop(node))
                loopInLoop.add(curr_path);
            getPathFromLoop(node.direct_next, curr_path, direct);
            getPathFromLoop(node.sub_next, curr_path, direct);
        } else if (node instanceof Branch) {
            if (!direct)
                branchInLoop.add(curr_path);
            for (Node branch_node : node.new_atoms)
                getPathFromLoop(branch_node, curr_path, direct);
            getPathFromLoop(node.direct_next, curr_path, direct);
        } else if (node instanceof Ques && !direct) {
            branchInLoop.add(curr_path);
            node.new_atoms = new Node[]{node.atom};
            getPathFromLoop(node.direct_next, curr_path, direct);
        } else if (node.direct_next != null)
            getPathFromLoop(node.direct_next, curr_path, direct);
        else if (node.sub_next != null)
            getPathFromLoop(node.sub_next, curr_path, direct);
    }

    private void removeInvalidLoop() {
        for (Iterator<Node> i = loopNodes.iterator(); i.hasNext(); ) {
            Node element = i.next();
            if (pattern.lengthExceed(element, maxLength))
                i.remove();
        }
    }

    private void initialize() {
        possible_vulnerability = false;

        loopNodes = new HashSet<Node>();
        loopInLoop = new ArrayList<ArrayList<Node>>();
        branchInLoop = new ArrayList<ArrayList<Node>>();
        loopAfterLoop = new ArrayList<ArrayList<Node>>();
        diyPaths = new ArrayList<ArrayList<Node>>();
        diyMatchs = new ArrayList<ArrayList<Set<Integer>>>();
        allMatchs = new ArrayList<ArrayList<ArrayList<Set<Integer>>>>();
        overlaps = new ArrayList<ArrayList<overlap>>();

        regex = pattern.pattern();
    }

    private void buildTree(Node cur) {
        if (pattern.isBacktrackLoop(cur))
            loopNodes.add(cur);

        // System.out.println("current node: " + cur.self);
        Set<Node> outNodes = new HashSet<Node>();
        getNextNodes(cur, outNodes);
        if (outNodes.size() == 0)
            return;
        else if (outNodes.size() == 1) {
            for (Node node : outNodes) {
                // System.out.println(" sub node: " + node.self);
                if (node.self == "BranchEnd" && !(cur instanceof Branch))
                    return;
                else if (cur.self == ")" && node.body != null) {
                    return;
                } else if (cur instanceof Branch) {
                    List<Node> filter_atoms = new ArrayList<Node>();
                    for (Node a : cur.atoms) {
                        if (a != null)
                            filter_atoms.add(a);
                    }
                    cur.new_atoms = filter_atoms.toArray(new Node[filter_atoms.size()]);
                    for (Node a : cur.new_atoms) {
                        a.direct_prev = cur;
                        buildTree(a);
                    }
                }
                cur.direct_next = node;
                node.direct_prev = cur;
                buildTree(node);
            }
        } else if (outNodes.size() == 2) {
            for (Node node : outNodes) {
                // System.out.println(" sub node: " + node.self);
                if (cur.body == node || cur.atom == node || cur.cond == node)
                    cur.sub_next = node;
                else if (node.self != "BranchEnd")
                    cur.direct_next = node;
                node.direct_prev = cur;
                buildTree(node);
            }
        } else {
            System.out.println("out node exceeds 2");
            for (Node node : outNodes)
                System.out.println(" sub node: " + node.self);
        }
    }

    private void getNextNodes(Node cur, Set<Node> outNodes) {
        // Curly
        if (cur.atom != null)
            outNodes.add(cur.atom);
        // if (cur.atom_self != null)
        // Branch
        // if (cur.new_atoms != null)
        // Conn
        if (cur.conn != null)
            outNodes.add(cur.conn);
        // Loop
        if (cur.body != null)
            outNodes.add(cur.body);
        // Prolog
        if (cur.loop != null)
            outNodes.add(cur.loop);
        // GroupRef
        if (cur.head != null)
            outNodes.add(cur.head);
        // Conditional
        if (cur.cond != null)
            outNodes.add(cur.cond);
        // if (cur.yes != null)
        // if (cur.not != null)
        // Next
        if (cur.next != null && cur.next.self != "Exit")
            outNodes.add(cur.next);
        // if (cur.next_self != null) outNodes.add(cur.next_self);
    }
}
package com.logaudit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Scans a source tree for logging calls and System.out/err prints.
 * Emits JSON Lines to stdout; redirect to logs.jsonl
 * <p>
 * Usage:
 * mvn -q -f scanner-java/pom.xml -DskipTests package
 * java -cp scanner-java/target/log-audit-1.0-SNAPSHOT.jar \
 * com.logaudit.LogScanner /path/to/java/src > logs.jsonl
 */
public class LogScanner {

    private static final Set<String> LOG_METHODS = Set.of(
            "trace", "debug", "info", "warn", "error", "fatal", "severe", "warning"
    );

    private static final Pattern SLF4J_PLACEHOLDER = Pattern.compile("\\{}");
    private static final Pattern PRINTF_PLACEHOLDER = Pattern.compile("%[a-zA-Z]");

    private static final ObjectMapper M = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Provide a directory to scan");
            System.exit(2);
        }
        Path root = Paths.get(args[0]);
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(p -> p.toString().endsWith(".java")).forEach(LogScanner::scanFile);
        }
    }

    private static void scanFile(Path p) {
        try {
            String code = Files.readString(p, StandardCharsets.UTF_8);
            CompilationUnit cu = StaticJavaParser.parse(code);
            cu.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodCallExpr call, Void arg) {
                    super.visit(call, arg);

                    // System.out.println / System.err.println
                    if (isSystemOutErr(call)) {
                        String level = call.getScope().get().toString().contains("err") ? "ERROR" : "INFO";
                        String msg = extractMessage(call);
                        emit(p, call, "SYSTEM", level, msg, call.getArguments());
                        return;
                    }

                    // Logger.* calls
                    Optional<Expression> scope = call.getScope();
                    if (scope.isPresent() && looksLikeLogger(scope.get())) {
                        String name = call.getNameAsString().toLowerCase(Locale.ROOT);
                        if (LOG_METHODS.contains(name)) {
                            String msg = extractMessage(call);
                            emit(p, call, "LOGGER", name.toUpperCase(Locale.ROOT), msg, call.getArguments());
                        }
                    }
                }
            }, null);
        } catch (Exception e) {
            System.err.println("Failed parsing " + p + ": " + e.getMessage());
        }
    }

    private static boolean isSystemOutErr(MethodCallExpr call) {
        if (!call.getNameAsString().startsWith("print")) return false;
        if (call.getScope().isEmpty()) return false;
        Expression s = call.getScope().get(); // e.g. System.out
        return s.isFieldAccessExpr() && s.toString().startsWith("System.out")
                || s.isFieldAccessExpr() && s.toString().startsWith("System.err");
    }

    private static boolean looksLikeLogger(Expression scope) {
        // Heuristic: variable/method chain named "log"/"logger" or typical factory getLogger(...)
        String s = scope.toString();
        return s.matches(".*\\blogger?\\b.*") || s.contains("getLogger(");
    }

    private static String extractMessage(MethodCallExpr call) {
        if (call.getArguments().isEmpty()) return "";
        Expression first = call.getArgument(0);

        // String literal
        if (first.isStringLiteralExpr()) {
            return first.asStringLiteralExpr().getValue();
        }
        // "concatenation" literal-ish
        if (first.isBinaryExpr()) {
            return flattenConcat(first);
        }
        // printf-style (message is arg0 for printf/format)
        if (isPrintfLike(call)) {
            return first.toString();
        }
        // fallback
        return first.toString();
    }

    private static boolean isPrintfLike(MethodCallExpr call) {
        String n = call.getNameAsString().toLowerCase(Locale.ROOT);
        return n.equals("printf") || n.equals("format");
    }

    private static String flattenConcat(Expression expr) {
        if (expr.isBinaryExpr() && expr.asBinaryExpr().getOperator() == BinaryExpr.Operator.PLUS) {
            return flattenConcat(expr.asBinaryExpr().getLeft()) + flattenConcat(expr.asBinaryExpr().getRight());
        }
        if (expr.isStringLiteralExpr()) {
            return expr.asStringLiteralExpr().getValue();
        }
        return "${expr}"; // marker for runtime expression
    }

    private static int countSlf4jPlaceholders(String s) {
        return (int) SLF4J_PLACEHOLDER.matcher(s).results().count();
    }

    private static int countPrintfPlaceholders(String s) {
        return (int) PRINTF_PLACEHOLDER.matcher(s).results().count();
    }

    private static void emit(Path file, MethodCallExpr call, String kind, String level, String msg, NodeList<Expression> args) {
        int line = call.getBegin().map(p -> p.line).orElse(-1);
        String rawMsg = msg == null ? "" : msg;
        int msgBytes = rawMsg.getBytes(StandardCharsets.UTF_8).length;

        // Format checks
        boolean usesConcat = msg.contains("${expr}");
        boolean isPrintf = isPrintfLike(call);
        int placeholderCount = isPrintf ? countPrintfPlaceholders(rawMsg) : countSlf4jPlaceholders(rawMsg);
        int nonMsgArgCount = Math.max(0, args.size() - 1);

        boolean placeholderMismatch = false;
        if (!isPrintf) {
            // SLF4J {} count should match number of non-message args (excluding throwable)
            int adjustedArgs = nonMsgArgCount;
            if (nonMsgArgCount > 0 && looksLikeThrowable(args.get(args.size() - 1))) {
                adjustedArgs -= 1;
            }
            placeholderMismatch = (placeholderCount != adjustedArgs);
        } else {
            placeholderMismatch = (placeholderCount != nonMsgArgCount);
        }

        boolean badFormat = usesConcat || placeholderMismatch;
        boolean isSystem = kind.equals("SYSTEM");

        ObjectNode n = M.createObjectNode();
        n.put("file", file.toString());
        n.put("line", line);
        n.put("kind", kind); // LOGGER or SYSTEM
        n.put("level", level);
        n.put("message_template", rawMsg);
        n.put("message_bytes", msgBytes);
        n.put("args_count", nonMsgArgCount);
        n.put("placeholder_count", placeholderCount);
        n.put("placeholder_mismatch", placeholderMismatch);
        n.put("uses_concat", usesConcat);
        n.put("is_system_out_err", isSystem);

        // quick “potentially unnecessary” heuristics
        String lower = rawMsg.toLowerCase(Locale.ROOT);
        boolean lowSignal = lower.matches(".*\\b(entering|exiting|here|test|todo|tmp|debug)\\b.*");
        boolean piiHint = lower.matches(".*\\b(pass(word)?|token|secret|cpf|ssn|credit|card)\\b.*");
        n.put("heuristic_unnecessary", lowSignal);
        n.put("heuristic_pii_risk", piiHint);

        System.out.println(n.toString());
    }

    private static boolean looksLikeThrowable(Expression e) {
        String s = e.toString();
        return s.endsWith(")") ? s.contains("Exception") || s.contains("Throwable") : s.contains("Exception");
    }
}

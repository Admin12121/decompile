import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class DumpAllDecompile extends GhidraScript {
    private Listing listing;
    private Memory memory;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: DumpAllDecompile.java <output-dir> [base-name] [timeout-seconds]");
        }

        String outDir = args[0];
        String baseName = args.length > 1 ? args[1] : currentProgram.getName();
        int timeoutSeconds = parseTimeout(args);

        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();

        File outputDirectory = new File(outDir);
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) {
            throw new IOException("Could not create output directory: " + outDir);
        }

        File pseudocodeFile = new File(outputDirectory, baseName + ".pseudocode.c");
        File disassemblyFile = new File(outputDirectory, baseName + ".disassembly.asm");
        File summaryFile = new File(outputDirectory, baseName + ".summary.txt");

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);

        int extractedFunctions = 0;
        int skippedExternalFunctions = 0;
        int decompiledFunctions = 0;
        int failedDecompiles = 0;
        int disassembledInstructions = 0;

        try (
            BufferedWriter pseudoWriter = new BufferedWriter(new FileWriter(pseudocodeFile, false));
            BufferedWriter asmWriter = new BufferedWriter(new FileWriter(disassemblyFile, false));
            BufferedWriter summaryWriter = new BufferedWriter(new FileWriter(summaryFile, false))
        ) {
            writeHeader(pseudoWriter, "GHIDRA PSEUDOCODE OUTPUT");
            writeHeader(asmWriter, "GHIDRA DISASSEMBLY OUTPUT");
            writeHeader(summaryWriter, "GHIDRA EXTRACTION SUMMARY");

            FunctionManager functionManager = currentProgram.getFunctionManager();
            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (!shouldExtract(function)) {
                    skippedExternalFunctions++;
                    continue;
                }

                extractedFunctions++;

                writeFunctionHeader(pseudoWriter, function);
                writeFunctionHeader(asmWriter, function);

                DecompileStatus status = decompileFunction(decompiler, function, timeoutSeconds, pseudoWriter);
                if (status == DecompileStatus.SUCCESS) {
                    decompiledFunctions++;
                }
                else {
                    failedDecompiles++;
                }

                disassembledInstructions += writeDisassembly(function, asmWriter);
            }

            writeTotals(pseudoWriter, extractedFunctions);
            writeTotals(asmWriter, extractedFunctions);
            writeSummary(
                summaryWriter,
                pseudocodeFile,
                disassemblyFile,
                extractedFunctions,
                skippedExternalFunctions,
                decompiledFunctions,
                failedDecompiles,
                disassembledInstructions
            );
        }
        finally {
            decompiler.dispose();
        }

        println("[+] Pseudocode saved to: " + pseudocodeFile.getAbsolutePath());
        println("[+] Disassembly saved to: " + disassemblyFile.getAbsolutePath());
        println("[+] Summary saved to: " + summaryFile.getAbsolutePath());
    }

    private int parseTimeout(String[] args) {
        if (args.length < 3) {
            return 120;
        }
        try {
            return Integer.parseInt(args[2]);
        }
        catch (NumberFormatException ignored) {
            return 120;
        }
    }

    private void writeHeader(BufferedWriter writer, String title) throws IOException {
        writer.write(title);
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
        writer.write("Program  : " + currentProgram.getName());
        writer.newLine();
        writer.write("Language : " + currentProgram.getLanguageID());
        writer.newLine();
        writer.write("Compiler : " + currentProgram.getCompilerSpec().getCompilerSpecID());
        writer.newLine();
        writer.write("ImageBase: " + currentProgram.getImageBase());
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
        writer.newLine();
    }

    private void writeFunctionHeader(BufferedWriter writer, Function function) throws IOException {
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
        writer.write("FUNCTION: " + function.getName());
        writer.newLine();
        writer.write("ADDRESS : " + function.getEntryPoint());
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
        writer.newLine();
    }

    private DecompileStatus decompileFunction(
        DecompInterface decompiler,
        Function function,
        int timeoutSeconds,
        BufferedWriter writer
    ) throws IOException {
        try {
            DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                writer.write(results.getDecompiledFunction().getC());
                writer.newLine();
                return DecompileStatus.SUCCESS;
            }

            String reason = results != null ? results.getErrorMessage() : "unknown error";
            writer.write("[!] Decompile failed: " + reason);
            writer.newLine();
            return DecompileStatus.FAILED;
        }
        catch (Exception e) {
            writer.write("[!] Error while decompiling: " + e.getMessage());
            writer.newLine();
            return DecompileStatus.FAILED;
        }
    }

    private boolean shouldExtract(Function function) {
        if (function.isExternal()) {
            return false;
        }

        MemoryBlock block = memory.getBlock(function.getEntryPoint());
        if (block == null) {
            return false;
        }

        return !"EXTERNAL".equalsIgnoreCase(block.getName());
    }

    private int writeDisassembly(Function function, BufferedWriter writer) throws IOException {
        int instructionCount = 0;
        try {
            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                writer.write(formatInstruction(instructions.next()));
                writer.newLine();
                instructionCount++;
            }

            if (instructionCount == 0) {
                writer.write("[!] No instructions found for function body");
                writer.newLine();
            }
        }
        catch (Exception e) {
            writer.write("[!] Error while disassembling: " + e.getMessage());
            writer.newLine();
        }
        return instructionCount;
    }

    private String formatInstruction(Instruction instruction) {
        String address = instruction.getAddress().toString();
        String bytes = instructionBytes(instruction);
        String text = instruction.toString();
        if (bytes.length() > 0) {
            return String.format("%-18s %-24s %s", address, bytes, text);
        }
        return String.format("%-18s %s", address, text);
    }

    private String instructionBytes(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                if (i > 0) {
                    builder.append(' ');
                }
                builder.append(String.format("%02x", bytes[i] & 0xff));
            }
            return builder.toString();
        }
        catch (Exception ignored) {
            return "";
        }
    }

    private void writeTotals(BufferedWriter writer, int extractedFunctions) throws IOException {
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
        writer.write("EXTRACTED FUNCTIONS: " + extractedFunctions);
        writer.newLine();
        writer.write(repeat("=", 100));
        writer.newLine();
    }

    private void writeSummary(
        BufferedWriter writer,
        File pseudocodeFile,
        File disassemblyFile,
        int extractedFunctions,
        int skippedExternalFunctions,
        int decompiledFunctions,
        int failedDecompiles,
        int disassembledInstructions
    ) throws IOException {
        writer.write("Pseudocode file          : " + pseudocodeFile.getAbsolutePath());
        writer.newLine();
        writer.write("Disassembly file        : " + disassemblyFile.getAbsolutePath());
        writer.newLine();
        writer.write("Extracted functions     : " + extractedFunctions);
        writer.newLine();
        writer.write("Skipped external funcs  : " + skippedExternalFunctions);
        writer.newLine();
        writer.write("Decompiled functions    : " + decompiledFunctions);
        writer.newLine();
        writer.write("Failed decompiles       : " + failedDecompiles);
        writer.newLine();
        writer.write("Disassembled instructions: " + disassembledInstructions);
        writer.newLine();
        writer.write("Memory blocks");
        writer.newLine();

        for (MemoryBlock block : memory.getBlocks()) {
            writer.write(String.format(
                "  %s %s-%s size=%d execute=%s write=%s",
                block.getName(),
                block.getStart(),
                block.getEnd(),
                block.getSize(),
                block.isExecute(),
                block.isWrite()
            ));
            writer.newLine();
        }
    }

    private String repeat(String value, int count) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < count; i++) {
            builder.append(value);
        }
        return builder.toString();
    }

    private enum DecompileStatus {
        SUCCESS,
        FAILED
    }
}

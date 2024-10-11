package de.dragon.main.ui;

import java.io.PrintStream;

/**
 * @author Dragon777 / Darkness4191
 * @version 10.0
 */

public class Progressbar {

    private PrintStream stout;
    private boolean print_percent;

    private String BAR_DESIGN = "[:::::::::::::::::::::::::::]";

    public Progressbar(PrintStream stream, boolean print_percent) {
        this.stout = stream;
        this.print_percent = print_percent;
        stream.print("");
    }

    public Progressbar(PrintStream stream, String bardesign, boolean print_percent) {
        this.stout = stream;
        this.print_percent = print_percent;
        this.BAR_DESIGN = bardesign;
        stream.print("");
    }

    public void update(double percent) {
        write(percent, "\r");
    }

    public void finish() {
        write(1, "\n");
    }

    private void write(double percent, String finalChar) {
        StringBuilder updated = new StringBuilder("[");
        for(int i = 0;  i < BAR_DESIGN.length() - 2; i++) {
            double b = i * 1D / (BAR_DESIGN.length() * 1D - 2);
            if(b < percent) {
                updated.append("#");
            } else {
                updated.append(BAR_DESIGN.charAt(i + 1));
            }
        }
        updated.append("]").append(print_percent ? " " + (Math.round(percent * 1000) / 10D) + "%" : "").append(finalChar);
        stout.print(updated.toString());
    }

}

package edu.fordham.cis.wisdm;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Handles the automatic scanning for common vulnerabilities, configuration files, and exposures that may
 * provide information that is valuable to analysts at a later point.
 * @author Andrew Johnston
 */
public class NiktoScanManager extends TimerTask {

    private static String NIKTO_CMD = "/nikto/path/here";

    private static String NIKTO_TEMP_FILE_PATH = "/tmp/nikto/file/path";

    private static AtomicBoolean IS_RUNNING = new AtomicBoolean(false);

    private static Logger logger = Logger.getLogger(NiktoScanManager.class);

    /**
     * For some configured interval, every new host should be scanned for vulnerabilties
     * and common exposures. This runs the Nikto tool on each new domain (as provided by an
     * independent RDBMS class) and takes the results (XML files) and makes them into pretty
     * JSON for storage in an NoSQL database.
     */
    public void run() {
        if (IS_RUNNING.get()) { // If a batch of scans is still running
            logger.warn("Previous Nikto Scan still running. This scan will be aborted.");
            return; //Don't do the scan
        }
        //If we get this far, no scan should currently be running
        IS_RUNNING.set(true);
        ArrayList<String> hosts = DatabaseManager.getDistinctNewHosts();
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(NIKTO_TEMP_FILE_PATH+"/hosts.txt"));
            for(String host : hosts) {
                writer.println(host.trim());
                writer.flush();
            }
            writer.flush(); //Flush a bit extra just to be safe
            writer.close();
            //Now that the host file is written, run the Nikto command on it
            Runtime runtime = Runtime.getRuntime();
            Process p = runtime.exec(NIKTO_CMD + " my args here");
            p.waitFor();
            //If we got this far, every host should have a file with the output
            //foreach file outputted
                //Convert the file into JSON
                //See http://stackoverflow.com/questions/1823264/quickest-way-to-convert-xml-to-json-in-java
        } catch (IOException e) {
            logger.debug("Failed to open writer for hosts. Nikto scan will not be performed this round.");
        } catch (InterruptedException e) {
            logger.debug("Failed to complete Nikto scan against hosts. All hosts will be rescanned at next interval.");
        } finally {
            //Prep for next run by cleaning out the directory and unsetting boolean
            File tempFolder = new File(NIKTO_TEMP_FILE_PATH);
            deleteFolder(tempFolder);
            IS_RUNNING.set(false);
        }

    }

    private void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if(files!=null) { //some JVMs return null for empty dirs
            for(File f: files) {
                if(f.isDirectory()) {
                    deleteFolder(f); //Shouldn't be necessary but left in for future-proofing
                } else {
                    f.delete();
                }
            }
        }
        //Future proofing: If its not the main directory, go ahead and delete it.
        if (!folder.getPath().equals(NIKTO_TEMP_FILE_PATH)) {
            folder.delete();
        }
    }
}

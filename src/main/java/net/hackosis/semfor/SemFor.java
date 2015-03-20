/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.hackosis.semfor;

import net.hackosis.semfor.parsers.VirusTotalParser;

/**
 *
 * @author root
 */
public class SemFor {
    public static void main(String[] args){
        SemFor app = new SemFor();
        app.parseEvidenceItems();
    }
    
    private void parseEvidenceItems(){
        VirusTotalParser vtParser = new VirusTotalParser();
        vtParser.printFileScanReport("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    }
}

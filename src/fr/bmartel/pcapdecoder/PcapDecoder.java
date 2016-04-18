/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Bertrand Martel
 * Copyright (c) 2016 Michal Genserek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fr.bmartel.pcapdecoder;

import fr.bmartel.pcapdecoder.constant.HeaderBlocks;
import fr.bmartel.pcapdecoder.constant.MagicNumber;
import fr.bmartel.pcapdecoder.structure.BlockTypes;
import fr.bmartel.pcapdecoder.structure.PcapNgStructureParser;
import fr.bmartel.pcapdecoder.structure.types.IPcapngType;
import fr.bmartel.pcapdecoder.utils.DecodeException;
import fr.bmartel.pcapdecoder.utils.DecoderStatus;
import fr.bmartel.pcapdecoder.utils.Endianess;
import fr.bmartel.pcapdecoder.utils.UtilFunctions;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PCAP NG decoder
 *
 * @author Bertrand Martel
 * @author Michal Genserek
 *
 */
public class PcapDecoder {

    private final static Logger LOG = Logger.getLogger(PcapDecoder.class.getName());
    private final int DEFAULT_BUFFER_LENGTH = 8192;
    private final int BLOCK_HEADER_LENGTH = 8;
    
    /**
     * data to parse
     */
    private final byte[] data;

    private ByteOrder currentEndian = ByteOrder.BIG_ENDIAN;
            
    private final ArrayList<IPcapngType> pcapSectionList = new ArrayList<>();
    
    private final InputStream inputStream;

    /**
     * instantiate Pcap Decoder with a new data to parse (from Pcap Ng file)
     *
     * @param data
     */
    public PcapDecoder(byte[] data) {
        this.data = data;
        inputStream = null;
    }
    
    /**
     * instantiate Pcap Decoder with an input stream
     *
     * @param stream
     */
    public PcapDecoder(InputStream stream) {
        this.data = new byte[DEFAULT_BUFFER_LENGTH];
        inputStream = stream;
    }
    
    /**
     * @return true if this instance is using stream to read data, false otherwise
     */
    public boolean isUsingStream() {
        return inputStream != null;
    }

    /**
     * Detect endianess with magic number in section header block : will be
     * 0x1A2B3C4D in big endian and 0x4D3C2B1A for little endian
     *
     * @param magicNumber
     * @return
     */
    private byte detectEndianness(byte[] magicNumber) {
        
        boolean isBigEndian = (currentEndian == ByteOrder.BIG_ENDIAN);
        
        if (UtilFunctions.compare32Bytes(MagicNumber.MAGIC_NUMBER_BIG_ENDIAN, magicNumber, isBigEndian)) {
            return Endianess.BIG_ENDIAN;
        } else if (UtilFunctions.compare32Bytes(MagicNumber.MAGIC_NUMBER_LITTLE_ENDIAN, magicNumber, isBigEndian)) {
            return Endianess.LITTLE_ENDIAN;
        } else {
            return Endianess.NO_ENDIANESS;
        }
    }

    private int parseBlockLength(byte[] length, boolean isBigEndian) {
        if (isBigEndian) {
            int blockLength = (((data[0] << 32) & 0xFF) + ((data[1] << 16) & 0xFF) + ((data[2] << 8) & 0xFF) + ((data[3]) & 0xFF));
            return blockLength;
        } else {
            int blockLength = (((length[0]) & 0xFF) + ((length[1] << 8) & 0xFF00) + ((length[2] << 16) & 0xFF0000) + ((length[3] << 32) & 0xFF000000));
            return blockLength;
        }
    }

    /**
     * Parse data block of all type of section and return current index to be
     * read next
     *
     * @param data
     * @return
     */
    private int parseDataBlock(BlockTypes type, byte[] data, int initIndex) {
        
        boolean isBigEndian = (currentEndian == ByteOrder.BIG_ENDIAN);
        
        try {
            int blockLength = parseBlockLength(Arrays.copyOfRange(data, initIndex + 4, initIndex + 8), isBigEndian);
            
            LOG.info("This Block size: " + blockLength);
            
            if (isUsingStream()) { // if we are using stream, load rest of the block to buffer
                LOG.info("Lazy load " + blockLength);
                lazyLoadBytesToBuffer(BLOCK_HEADER_LENGTH, blockLength - BLOCK_HEADER_LENGTH);
            }

            // substract 4 for header and 4 for size (x2 at the end)
            byte[] dataBlock = Arrays.copyOfRange(data, initIndex + 8, initIndex + (blockLength - 4));

            byte[] dataTemp = dataBlock;

            if (type == BlockTypes.SECTION_HEADER_BLOCK) {
                dataTemp = Arrays.copyOfRange(dataBlock, 4, dataBlock.length);
            }
            PcapNgStructureParser structure = new PcapNgStructureParser(type, dataTemp, isBigEndian);
            structure.decode();
            pcapSectionList.add(structure.getPcapStruct());

            initIndex += (blockLength - 1) + 1;
            return initIndex;
        } catch (Exception e) {
            LOG.log(Level.WARNING, e, null);
            return DecoderStatus.FAILED_STATUS;
        }
    }

    /**
     * Decode a specific section type from HeaderBLocks class
     *
     * @param type
     * @param initIndex
     * @return 
     * @throws fr.bmartel.pcapdecoder.utils.DecodeException
     */
    public int processSectionType(BlockTypes type, int initIndex) throws DecodeException {
        
        boolean isBigEndian = (currentEndian == ByteOrder.BIG_ENDIAN);
        
        if (UtilFunctions.compare32Bytes(HeaderBlocks.SECTION_TYPE_LIST.get(type.toString()), Arrays.copyOfRange(data, initIndex, initIndex + 4), isBigEndian)) {
            if (type == BlockTypes.SECTION_HEADER_BLOCK) {
                byte endianess = detectEndianness(Arrays.copyOfRange(Arrays.copyOfRange(data, initIndex + 8, initIndex + 12), 0, 4));

                switch (endianess) {
                    case Endianess.BIG_ENDIAN:
                        currentEndian = ByteOrder.BIG_ENDIAN;
                        LOG.info("BIG_ENDIAN detected in current data.");
                        break;
                    case Endianess.LITTLE_ENDIAN:
                        currentEndian = ByteOrder.LITTLE_ENDIAN;
                        LOG.info("LITTLE_ENDIAN detected in current data.");
                        break;
                    default:
                        String message = "Unable to parse ENDIANESS from SECTION_HEADER_BLOCK!";
                        LOG.severe(message);
                        throw new DecodeException(message);
                }
            }

            initIndex = parseDataBlock(type, data, initIndex);

            if (initIndex == -1) {
                throw new DecodeException();
            }
            return initIndex;
        }
        return initIndex;
    }
    
    private int lazyLoadBytesToBuffer(int off, int len) {
        try {
            return inputStream.read(data, off, len);
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, ex, null);
            return -2;
        }
    }

    public IPcapngType decodeNext() throws DecodeException {
        if (!isUsingStream()) {
            LOG.warning("This instance is not using InputStream to parse data. Use decode() instead.");
            return null;
        }

        pcapSectionList.clear(); // clear previous entry
        int initIndex = 0; // we always start from beggining of buffer
        
        int br = lazyLoadBytesToBuffer(0, BLOCK_HEADER_LENGTH);
        
        if (br == -2) { // I/O Exception
            throw new DecodeException("Unable to read from InputStream.");
        }
        else if (br == -1) { // End of stream
            return null;
        }
        
        for (BlockTypes blockType: BlockTypes.values()) {
            int iValue = processSectionType(BlockTypes.SECTION_HEADER_BLOCK, initIndex);
            
            if (iValue != initIndex) {
                //initIndex = iValue;
                LOG.log(Level.INFO, "Found BLOCK of type: {0}", blockType.toString());
                break;
            }
        }
        
        if (pcapSectionList.isEmpty()) { // unknown block
            LOG.warning("Error input data format error");
            throw new DecodeException("File parsing error | format not recognized");
        }

        return pcapSectionList.get(0);
    }
    
    /**
     * Decode
     *
     * @return 
     */
    public byte decode() {
        if (isUsingStream()) {
            LOG.warning("This instance is using InputStream to parse data. Use decodeNext() instead.");
            return DecoderStatus.FAILED_STATUS;
        }
        
        if (data == null || data.length < 4) {
            LOG.warning("Error input data format error");
            return DecoderStatus.FAILED_STATUS;
        }

        int initIndex = 0;

        try {
            int formerIndex = 0;

            while (initIndex != data.length) {
                initIndex = processSectionType(BlockTypes.SECTION_HEADER_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.INTERFACE_DESCRIPTION_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.ENHANCES_PACKET_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.SIMPLE_PACKET_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.NAME_RESOLUTION_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.INTERFACE_STATISTICS_BLOCK, initIndex);
                initIndex = processSectionType(BlockTypes.PACKET_BLOCK, initIndex);

                if (formerIndex == initIndex && formerIndex != 0) {
                    throw new DecodeException("File parsing error | format not recognized");
                }
                formerIndex = initIndex;
            }
        } catch (DecodeException e) {
            LOG.log(Level.WARNING, e.getCause(), null);
            return DecoderStatus.FAILED_STATUS;
        }
        return DecoderStatus.SUCCESS_STATUS;
    }

    public ArrayList<IPcapngType> getSectionList() {
        return pcapSectionList;
    }
}

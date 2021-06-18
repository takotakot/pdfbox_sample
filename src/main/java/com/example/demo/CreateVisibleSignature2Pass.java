/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pdfbox.examples.signature;

import java.awt.Color;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.PrivateKey;

import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Enumeration;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Hex;
import org.apache.pdfbox.util.Matrix;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * This is a second example for visual signing a pdf. It doesn't use the "design pattern" influenced
 * PDVisibleSignDesigner, and doesn't create its complex multilevel forms described in the Adobe
 * document
 * <a href="https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/PPKAppearances.pdf">Digital
 * Signature Appearances</a>, because this isn't required by the PDF specification. See the
 * discussion in December 2017 in PDFBOX-3198.
 *
 * @author Vakhtang Koroghlishvili
 * @author Tilman Hausherr
 */
public class CreateVisibleSignature2Pass extends CreateSignatureBase
{
    private SignatureOptions signatureOptions;
    private boolean lateExternalSigning = false;
    private boolean makingPunchhole = false;
    private boolean insertingSignature = false;
    private File imageFile = null;

    private KeyStore keystore = null;
    private char[] pin = null;

    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that
     * should be used for the signature.
     *
     * @param keystore is a pkcs12 keystore.
     * @param pin is the pin for the keystore / private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     * @throws IOException if no certificate could be found
     */
    public CreateVisibleSignature2Pass(KeyStore keystore, char[] pin)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
    {
        super(keystore, pin);
        this.keystore = keystore;
        this.pin = pin;
    }

    public File getImageFile()
    {
        return imageFile;
    }

    public void setImageFile(File imageFile)
    {
        this.imageFile = imageFile;
    }

    public boolean isLateExternalSigning()
    {
        return lateExternalSigning;
    }

    /**
     * Set late external signing. Enable this if you want to activate the demo code where the
     * signature is kept and added in an extra step without using PDFBox methods. This is disabled
     * by default.
     *
     * @param lateExternalSigning
     */
    public void setLateExternalSigning(boolean lateExternalSigning)
    {
        this.lateExternalSigning = lateExternalSigning;
    }

    // public InputStream getDataToSign() throws IOException
    // {
    //     if (incrementPart == null || incrementalInput == null)
    //     {
    //         throw new IllegalStateException("PDF not prepared for signing");
    //     }
    //     // range of incremental bytes to be signed (includes /ByteRange but not /Contents)
    //     int incPartSigOffset = (int) (signatureOffset - incrementalInput.length());
    //     int afterSigOffset = incPartSigOffset + (int) signatureLength;
    //     int[] range =
    //     {
    //         0, incPartSigOffset,
    //         afterSigOffset, incrementPart.length - afterSigOffset
    //     };

    //     return new SequenceInputStream(
    //             new RandomAccessInputStream(incrementalInput),
    //             new COSFilterInputStream(incrementPart, range));
    // }

    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @throws IOException
     */
    public void signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl) throws IOException
    {
        this.signPDF(inputFile, signedFile, humanRect, tsaUrl, null);
    }

    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @param signatureFieldName optional name of an existing (unsigned) signature field
     * @throws IOException
     */
    public void signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl, String signatureFieldName) throws IOException
    {
        if (inputFile == null || !inputFile.exists())
        {
            throw new IOException("Document for signing does not exist");
        }

        setTsaUrl(tsaUrl);

        // creating output document and prepare the IO streams.

        try (FileOutputStream fos = new FileOutputStream(signedFile);
                PDDocument doc = Loader.loadPDF(inputFile))
        {
            int accessPermissions = SigUtils.getMDPPermission(doc);
            if (accessPermissions == 1)
            {
                throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
            }
            // Note that PDFBox has a bug that visual signing on certified files with permission 2
            // doesn't work properly, see PDFBOX-3699. As long as this issue is open, you may want to
            // be careful with such files.

            PDSignature signature = null;

            if(isInsertingSignature()) {
                signature = doc.getLastSignatureDictionary();

                // ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);
                // // invoke external signature service
                File contentOnlyFile = new File(inputFile.getParent(), "contentonly.pdf");
                System.err.println("calc hash:");
                byte[] hash = null;
                {
                    // hash
                    hash = calcHashFromContent(new FileInputStream(contentOnlyFile));
                    // System.err.println(Hex.getBytes(hash));
                }

                FileInputStream contentOnlyFileStream = new FileInputStream(contentOnlyFile);
                byte[] cmsSignature = sign(contentOnlyFileStream);

                // remember the offset (add 1 because of "<")
                int offset = signature.getByteRange()[0] + signature.getByteRange()[1] + 1;

                // Assure cmsSignature size is less than range.
                int range = (signature.getByteRange()[2] - 1) - offset;

                // copy file contents
                {
                    FileOutputStream newFile = new FileOutputStream(signedFile);
                    FileInputStream oldFile = new FileInputStream(inputFile);
                    oldFile.transferTo(newFile);
                    newFile.close();
                    oldFile.close();
                }

                if(Hex.getBytes(cmsSignature).length > range) {
                    throw new IOException("Can't write signature, not enough space");
                }

                // now write the signature at the correct offset without any PDFBox methods
                try (RandomAccessFile raf = new RandomAccessFile(signedFile, "rw"))
                {
                    raf.seek(offset);

                    try{
                        cmsSignature = createCMSSignatureFromHashAndKeystore(hash, this.keystore, this.pin);
                        System.err.println("length: " + cmsSignature.length);
                        raf.write(Hex.getBytes(cmsSignature));
                    }catch(Exception e){
                        System.err.println("exception: " + e.getMessage());
                        throw new IOException(e.getMessage());
                    }

                    // FileInputStream pkcs7sig = new FileInputStream(new File(inputFile.getParent(), "pkcs7_signature3.sgn"));
                    // raf.write(Hex.getBytes(IOUtils.toByteArray(pkcs7sig)));
                    // pkcs7sig.close();

                    // System.err.println("length: " + cmsSignature.length);
                    // System.err.println("length2: " + Hex.getBytes(cmsSignature).length);
                    // System.err.println("last: " + cmsSignature[cmsSignature.length -7]);
                }
                contentOnlyFileStream.close();

                // FileOutputStream cmsStream = new FileOutputStream(new File(inputFile.getParent(), "cmssignature.sgn"));
                // cmsStream.write(cmsSignature);
                // cmsStream.close();
            }else{
                PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
                PDRectangle rect = null;

                // sign a PDF with an existing empty signature, as created by the CreateEmptySignatureForm example.
                if (acroForm != null)
                {
                    signature = findExistingSignature(acroForm, signatureFieldName);
                    if (signature != null)
                    {
                        rect = acroForm.getField(signatureFieldName).getWidgets().get(0).getRectangle();
                    }
                }

                if (signature == null)
                {
                    // create signature dictionary
                    signature = new PDSignature();
                }

                if (rect == null)
                {
                    rect = createSignatureRectangle(doc, humanRect);
                }

                // Optional: certify
                // can be done only if version is at least 1.5 and if not already set
                // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
                // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
                if (doc.getVersion() >= 1.5f && accessPermissions == 0)
                {
                    SigUtils.setMDPPermission(doc, signature, 2);
                }

                if (acroForm != null && acroForm.getNeedAppearances())
                {
                    // PDFBOX-3738 NeedAppearances true results in visible signature becoming invisible 
                    // with Adobe Reader
                    if (acroForm.getFields().isEmpty())
                    {
                        // we can safely delete it if there are no fields
                        acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
                        // note that if you've set MDP permissions, the removal of this item
                        // may result in Adobe Reader claiming that the document has been changed.
                        // and/or that field content won't be displayed properly.
                        // ==> decide what you prefer and adjust your code accordingly.
                    }
                    else
                    {
                        System.out.println("/NeedAppearances is set, signature may be ignored by Adobe Reader");
                    }
                }

                // default filter
                signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

                // subfilter for basic and PAdES Part 2 signatures
                signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

                signature.setName("Name");
                signature.setLocation("Location");
                signature.setReason("Reason");

                // the signing date, needed for valid signature
                signature.setSignDate(Calendar.getInstance());

                // do not set SignatureInterface instance, if external signing used
                SignatureInterface signatureInterface = isExternalSigning() ? null : this;

                // register signature dictionary and sign interface
                signatureOptions = new SignatureOptions();

                // System.err.println("signatureOptions.getPreferredSignatureSize(): " + signatureOptions.getPreferredSignatureSize());
                // 0

                signatureOptions.setVisualSignature(createVisualSignatureTemplate(doc, 0, rect, signature));
                signatureOptions.setPage(0);
                // if(! isMakePunchhole()) {
                    doc.addSignature(signature, signatureInterface, signatureOptions);
                // }

                // signatureOptions.DEFAULT_SIGNATURE_SIZE 9472

                if (isExternalSigning())
                {
                    ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);
                    // invoke external signature service

                    InputStream content = externalSigning.getContent();
                    File contentOnlyFile = new File(inputFile.getParent(), "contentonly.pdf");
                    FileOutputStream contentOnlyFileStream = new FileOutputStream(contentOnlyFile);
                    content.transferTo(contentOnlyFileStream);
                    contentOnlyFileStream.close();
                    
                    // byte[] cmsSignature = sign(content);

                    // Explanation of late external signing (off by default):
                    // If you want to add the signature in a separate step, then set an empty byte array
                    // and call signature.getByteRange() and remember the offset signature.getByteRange()[1]+1.
                    // you can write the ascii hex signature at a later time even if you don't have this
                    // PDDocument object anymore, with classic java file random access methods.
                    // If you can't remember the offset value from ByteRange because your context has changed,
                    // then open the file with PDFBox, find the field with findExistingSignature() or
                    // PDDocument.getLastSignatureDictionary() and get the ByteRange from there.
                    // Close the file and then write the signature as explained earlier in this comment.
                    // if (isLateExternalSigning())
                    if (isInsertingSignature())
                    {
                        // this saves the file with a 0 signature
                        externalSigning.setSignature(new byte[0]);

                        // remember the offset (add 1 because of "<")
                        int offset = signature.getByteRange()[1] + 1;

                        // now write the signature at the correct offset without any PDFBox methods
                        try (RandomAccessFile raf = new RandomAccessFile(signedFile, "rw"))
                        {
                            raf.seek(offset);
                            // raf.write(Hex.getBytes(cmsSignature));
                        }
                    }
                    else
                    {
                        // set signature bytes received from the service and save the file
                        // externalSigning.setSignature(cmsSignature);
                        externalSigning.setSignature(new byte[0]);

                        System.err.println("external write");
                    }
                }
                else
                {
                    // write incremental (only for signing purpose)
                    doc.saveIncremental(fos);
                    System.err.println("normal");
                }
            }
        }
        
        // Do not close signatureOptions before saving, because some COSStream objects within
        // are transferred to the signed document.
        // Do not allow signatureOptions get out of scope before saving, because then the COSDocument
        // in signature options might by closed by gc, which would close COSStream objects prematurely.
        // See https://issues.apache.org/jira/browse/PDFBOX-3743
        IOUtils.closeQuietly(signatureOptions);
    }

    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect)
    {
        float x = (float) humanRect.getX();
        float y = (float) humanRect.getY();
        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
        PDPage page = doc.getPage(0);
        PDRectangle pageRect = page.getCropBox();
        PDRectangle rect = new PDRectangle();
        // signing should be at the same position regardless of page rotation.
        switch (page.getRotation())
        {
            case 90:
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                break;
            case 180:
                rect.setUpperRightX(pageRect.getWidth() - x);
                rect.setLowerLeftX(pageRect.getWidth() - x - width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
            case 270:
                rect.setLowerLeftY(pageRect.getHeight() - x - width);
                rect.setUpperRightY(pageRect.getHeight() - x);
                rect.setLowerLeftX(pageRect.getWidth() - y - height);
                rect.setUpperRightX(pageRect.getWidth() - y);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(pageRect.getHeight() - y - height);
                rect.setUpperRightY(pageRect.getHeight() - y);
                break;
        }
        return rect;
    }

    // create a template PDF document with empty signature and return it as a stream.
    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum, 
            PDRectangle rect, PDSignature signature) throws IOException
    {
        try (PDDocument doc = new PDDocument())
        {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            float height = bbox.getHeight();
            Matrix initialScale = null;
            switch (srcDoc.getPage(pageNum).getRotation())
            {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2)); 
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 0:
                default:
                    break;
            }
            form.setBBox(bbox);
            PDFont font = PDType1Font.HELVETICA_BOLD;

            // from PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream))
            {
                // for 90° and 270° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null)
                {
                    cs.transform(initialScale);
                }

                // show background (just for debugging, to see the rect size + position)
                cs.setNonStrokingColor(Color.yellow);
                cs.addRect(-5000, -5000, 10000, 10000);
                cs.fill();

                if (imageFile != null)
                {
                    // show background image
                    // save and restore graphics if the image is too large and needs to be scaled
                    cs.saveGraphicsState();
                    cs.transform(Matrix.getScaleInstance(0.25f, 0.25f));
                    PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
                    cs.drawImage(img, 0, 0);
                    cs.restoreGraphicsState();
                }

                // show text
                float fontSize = 10;
                float leading = fontSize * 1.5f;
                cs.beginText();
                cs.setFont(font, fontSize);
                cs.setNonStrokingColor(Color.black);
                cs.newLineAtOffset(fontSize, height - leading);
                cs.setLeading(leading);

                X509Certificate cert = (X509Certificate) getCertificateChain()[0];

                // https://stackoverflow.com/questions/2914521/
                X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
                RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
                String name = IETFUtils.valueToString(cn.getFirst().getValue());

                // See https://stackoverflow.com/questions/12575990
                // for better date formatting
                String date = signature.getSignDate().getTime().toString();
                String reason = signature.getReason();

                cs.showText("Signer: " + name);
                cs.newLine();
                cs.showText(date);
                cs.newLine();
                cs.showText("Reason: " + reason);

                cs.endText();
            }

            // no need to set annotations and /P entry

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public byte[] calcHashFromContent(InputStream content) throws IOException
    {
        // Digest generation step
        byte[] digest = null;
        try
        {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA256", "BC");
            digest = md.digest(IOUtils.toByteArray(content));
            String digestStr = new String(org.apache.commons.codec.binary.Hex.encodeHex(digest));
            System.err.println("digest:" + digestStr);
        } catch (Exception e) {
            //             e.printStackTrace();
            throw new IOException(e);
        }
        return digest;
    }

    public byte[] createCMSSignatureFromHashAndKeystore(byte[] hash, KeyStore keystore, char[] pin) throws Exception {
        // Start key management
        PrivateKey pk = null;

        // grabs the first alias from the keystore and get the private key. An
        // alternative method or constructor could be used for setting a specific
        // alias that should be used.
        Enumeration<String> aliases = keystore.aliases();
        String alias;
        Certificate cert = null;
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        List<Certificate> certList = null;
        JcaCertStore certs = null;

        while (cert == null && aliases.hasMoreElements())
        {
            alias = aliases.nextElement();
            // setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            pk = (PrivateKey) keystore.getKey(alias, pin);
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if (certChain != null)
            {
                setCertificateChain(certChain);
                cert = certChain[0];
                if (cert instanceof X509Certificate)
                {
                    // avoid expired certificate
                    ((X509Certificate) cert).checkValidity();

                    SigUtils.checkCertificateUsage((X509Certificate) cert);
                }
                certList = Arrays.asList(keystore.getCertificateChain(alias));
                certs = new JcaCertStore(certList);
            }
        }

        if (cert == null)
        {
            throw new IOException("Could not find certificate");
        }
        // End key management


        byte [] cms = null;
        try
        {
            // Separate signature container creation step
            // List<Certificate> certList = Arrays.asList(chain);
            // JcaCertStore certs = new JcaCertStore(certList);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            Attribute attr = new Attribute(CMSAttributes.messageDigest,
                    new DERSet(new DEROctetString(hash)));

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(attr);

            SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                    .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));

            AlgorithmIdentifier sha256withRSA = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");

            // CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            // InputStream in = new ByteArrayInputStream(chain[0].getEncoded());
            // X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

            gen.addSignerInfoGenerator(builder.build(
                    new BcRSAContentSignerBuilder(sha256withRSA,
                            new DefaultDigestAlgorithmIdentifierFinder().find(sha256withRSA))
                                    .build(PrivateKeyFactory.createKey(pk.getEncoded())),
                    new JcaX509CertificateHolder(((X509Certificate) cert))));

            gen.addCertificates(certs);

            CMSSignedData s = gen.generate(new CMSAbsentContent(), false);
            cms = s.getEncoded();
            return cms;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            // throw new Exception(e);
        }
        return cms;
    }

    // Find an existing signature (assumed to be empty). You will usually not need this.
    private PDSignature findExistingSignature(PDAcroForm acroForm, String sigFieldName)
    {
        PDSignature signature = null;
        PDSignatureField signatureField;
        if (acroForm != null)
        {
            signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
            if (signatureField != null)
            {
                // retrieve signature dictionary
                signature = signatureField.getSignature();
                if (signature == null)
                {
                    signature = new PDSignature();
                    // after solving PDFBOX-3524
                    // signatureField.setValue(signature)
                    // until then:
                    signatureField.getCOSObject().setItem(COSName.V, signature);
                }
                else
                {
                    throw new IllegalStateException("The signature field " + sigFieldName + " is already signed.");
                }
            }
        }
        return signature;
    }

    public void setMakingPunchhole(boolean makingPunchhole)
    {
        this.makingPunchhole = makingPunchhole;
    }

    public boolean isMakePunchhole()
    {
        return makingPunchhole;
    }

    public void setInsertingSignature(boolean insertingSignature)
    {
        this.insertingSignature = insertingSignature;
    }

    public boolean isInsertingSignature()
    {
        return insertingSignature;
    }

    /**
     * Arguments are
     * [0] key store
     * [1] pin
     * [2] document that will be signed
     * [3] image of visible signature
     *
     * @param args
     * @throws java.security.KeyStoreException
     * @throws java.security.cert.CertificateException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.UnrecoverableKeyException
     */
    public static void main(String[] args) throws KeyStoreException, CertificateException,
            IOException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (args.length < 3)
        {
            usage();
            System.exit(1);
        }

        String tsaUrl = null;
        // External signing is needed if you are using an external signing service, e.g. to sign
        // several files at once.
        boolean externalSig = false;
        boolean makingPunchhole = false;
        boolean insertingSignature = false;
        for (int i = 0; i < args.length; i++)
        {
            if ("-tsa".equals(args[i]))
            {
                i++;
                if (i >= args.length)
                {
                    usage();
                    System.exit(1);
                }
                tsaUrl = args[i];
            }
            if ("-e".equals(args[i]))
            {
                externalSig = true;
            }
            if ("-punch".equals(args[i]))
            {
                makingPunchhole = true;
                externalSig = true;
            }
            if ("-insert".equals(args[i]))
            {
                insertingSignature = true;
                externalSig = true;
            }
        }
        if (makingPunchhole && insertingSignature)
        {
            usage();
            System.exit(1);
        }

        File ksFile = new File(args[0]);
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] pin = args[1].toCharArray();
        keystore.load(new FileInputStream(ksFile), pin);

        File documentFile = new File(args[2]);

        CreateVisibleSignature2Pass signing = new CreateVisibleSignature2Pass(keystore, pin.clone());

        if (args.length >= 4 && !"-tsa".equals(args[3]))
        {
            signing.setImageFile(new File(args[3]));
        }

        File signedDocumentFile;
        String name = documentFile.getName();
        String substring = name.substring(0, name.lastIndexOf('.'));
        signedDocumentFile = new File(documentFile.getParent(), substring + "_punch.pdf");

        signing.setExternalSigning(externalSig);
        signing.setMakingPunchhole(makingPunchhole);
        signing.setInsertingSignature(insertingSignature);

        // Set the signature rectangle
        // Although PDF coordinates start from the bottom, humans start from the top.
        // So a human would want to position a signature (x,y) units from the
        // top left of the displayed page, and the field has a horizontal width and a vertical height
        // regardless of page rotation.
        Rectangle2D humanRect = new Rectangle2D.Float(100, 200, 150, 50);

        signing.signPDF(documentFile, signedDocumentFile, humanRect, tsaUrl, "Signature1");
    }

    /**
     * This will print the usage for this program.
     */
    private static void usage()
    {
        System.err.println("Usage: java " + CreateVisibleSignature2Pass.class.getName()
                + " <pkcs12-keystore-file> <pin> <input-pdf> <sign-image>\n" + "" +
                           "options:\n" +
                           "  -tsa <url>    sign timestamp using the given TSA server\n"+
                           "  -e            sign using external signature creation scenario\n"+
                           "  -punch        create a punch hole for sign(1st pass) -e assumed"+
                           "  -insert       insert signature to the punch hole(2nd pass) -e assumed");

        // generate pkcs12-keystore-file with
        // keytool -storepass 123456 -storetype PKCS12 -keystore file.p12 -genkey -alias client -keyalg RSA
    }

}

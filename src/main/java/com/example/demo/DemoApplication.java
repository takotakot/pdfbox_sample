package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		// SpringApplication.run(DemoApplication.class, args);
		try (PDDocument doc = new PDDocument()) {

			PDPage page = new PDPage(PDRectangle.A4);
			doc.addPage(page);
	
			setupText(doc, page);
	
			doc.save("build/example1.pdf");
	
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	private static void setupText(PDDocument doc, PDPage page) {

		try (PDPageContentStream content = new PDPageContentStream(doc, page)) {
	
			content.beginText();
	
			PDFont font = PDType1Font.HELVETICA_BOLD;
			content.setFont(font, 12);
			content.newLineAtOffset(100, 700);
			content.showText("Hello World");
	
			content.endText();
	
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
import { launchPuppeteer } from 'crawlee';
import fs from 'fs/promises';
import path from 'path';

async function captureScreenshot(url, screenshot_path) {
    try {
        // create output directory
        // await fs.mkdir(output_path, { recursive: true });

        // start Puppeteer
        const browser = await launchPuppeteer();
        const page = await browser.newPage();

        // access the URL
        await page.goto(url, { waitUntil: 'networkidle2' });

        try {
            // take a screenshot of the page
            const screenshotBuffer = await page.screenshot({ fullPage: true });
            
            // save the screenshot to a file
            await fs.writeFile(screenshot_path, screenshotBuffer);
            console.log(`Screenshot saved to ${screenshot_path}`);
        } catch (error) {
            console.error(`Error taking screenshot: ${error}`);
            process.exit(1);    
        }

        await browser.close();

    } catch (error) {
        console.error(`Error launching Puppeteer: ${error}`);
        process.exit(1);
    }
}

// get the URL and output path from the command line arguments
captureScreenshot(process.argv[2], process.argv[3]);

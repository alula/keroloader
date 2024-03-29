package io.github.alula.keroloader2;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.MatrixCursor.RowBuilder;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import android.util.Log;
import android.webkit.MimeTypeMap;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;

public class DoukutsuDocumentsProvider extends DocumentsProvider {
    private final static String[] DEFAULT_ROOT_PROJECTION =
            new String[]{
                    Root.COLUMN_DOCUMENT_ID,
                    Root.COLUMN_ROOT_ID,
                    Root.COLUMN_ICON,
                    Root.COLUMN_TITLE,
                    Root.COLUMN_MIME_TYPES,
                    Root.COLUMN_AVAILABLE_BYTES,
                    Root.COLUMN_FLAGS
            };

    private final static String[] DEFAULT_DOCUMENT_PROJECTION =
            new String[]{
                    Document.COLUMN_DOCUMENT_ID,
                    Document.COLUMN_DISPLAY_NAME,
                    Document.COLUMN_SIZE,
                    Document.COLUMN_LAST_MODIFIED,
                    Document.COLUMN_MIME_TYPE,
                    Document.COLUMN_FLAGS
            };

    @Override
    public Cursor queryRoots(String[] projection) throws FileNotFoundException {
        File file = getContext().getFilesDir();
        String id = file.getAbsolutePath();
        Log.d(DoukutsuDocumentsProvider.class.getName(), "files dir location: " + id);

        MatrixCursor result = new MatrixCursor(projection != null ?
                projection : DEFAULT_ROOT_PROJECTION);

        RowBuilder row = result.newRow();

        row.add(Root.COLUMN_DOCUMENT_ID, id);
        row.add(Root.COLUMN_ROOT_ID, id);
        row.add(Root.COLUMN_ICON, R.mipmap.ic_launcher);
        row.add(Root.COLUMN_TITLE,
                getContext().getString(R.string.document_provider_name));
        row.add(Root.COLUMN_MIME_TYPES, "*/*");
        row.add(Root.COLUMN_AVAILABLE_BYTES, file.getFreeSpace());
        row.add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_IS_CHILD | Root.FLAG_SUPPORTS_CREATE);

        return result;
    }

    @Override
    public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DEFAULT_DOCUMENT_PROJECTION);

        pushFile(result, new File(documentId));

        return result;
    }

    @Override
    public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder) throws FileNotFoundException {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : DEFAULT_DOCUMENT_PROJECTION);

        File root = new File(parentDocumentId);

        if (!root.exists()) {
            throw new FileNotFoundException("No such file: " + root.getAbsolutePath());
        }

        if (!root.isDirectory()) {
            return null;
        }

        File[] files = root.listFiles();
        if (files != null) {
            for (File file : files) {
                pushFile(result, file);
            }
        }

        return result;
    }

    @Override
    public ParcelFileDescriptor openDocument(String documentId, String mode, @Nullable CancellationSignal signal) throws FileNotFoundException {
        File file = new File(documentId);
        int imode = ParcelFileDescriptor.parseMode(mode);
        return ParcelFileDescriptor.open(file, imode);
    }

    @Override
    public String createDocument(String parentDocumentId, String mimeType, String displayName) throws FileNotFoundException {
        File file = new File(parentDocumentId, displayName);

        if (file.exists()) {
            int nextId = 1;

            while (file.exists()) {
                // maybe let's put the id before extension?
                file = new File(parentDocumentId, String.format("%s (%d)", displayName, nextId));

                ++nextId;
            }
        }

        try {
            if (mimeType != null && mimeType.equals(Document.MIME_TYPE_DIR)) {
                if (!file.mkdir()) {
                    throw new FileNotFoundException("Couldn't create directory: " + file.getAbsolutePath());
                }
            } else {
                if (!file.createNewFile()) {
                    throw new FileNotFoundException("Couldn't create file: " + file.getAbsolutePath());
                }
            }
        } catch (IOException e) {
            throw new FileNotFoundException("Couldn't create file: " + e.getMessage());
        }

        return file.getAbsolutePath();
    }

    @Override
    public void deleteDocument(String documentId) throws FileNotFoundException {
        File file = new File(documentId);

        if (!file.exists()) {
            throw new FileNotFoundException("Couldn't find file: " + file.getAbsolutePath());
        }

        deleteRecursive(file);
        // todo refresh this shit
        // getContext().getContentResolver().refresh()
    }

    @Override
    public String getDocumentType(String documentId) throws FileNotFoundException {
        File file = new File(documentId);

        if (!file.exists()) {
            throw new FileNotFoundException("Couldn't find file: " + file.getAbsolutePath());
        } else if (file.isDirectory()) {
            return Document.MIME_TYPE_DIR;
        } else if (file.isFile()) {
            return getMimeType(file.getAbsolutePath());
        }

        return null;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public boolean isChildDocument(String parentDocumentId, String documentId) {
        return documentId.startsWith(parentDocumentId);
    }

    @Override
    public String renameDocument(String documentId, String displayName) throws FileNotFoundException {
        File file = new File(documentId);

        if (!file.exists()) {
            throw new FileNotFoundException("Couldn't find file: " + file.getAbsolutePath());
        }

        File newPath = new File(file.getParentFile().getAbsolutePath() + "/" + displayName);

        try {
            Files.move(file.toPath(), newPath.toPath());
        } catch (IOException e) {
            throw new FileNotFoundException(e.getMessage());
        }

        return newPath.getAbsolutePath();
    }

    @Override
    public void removeDocument(String documentId, String parentDocumentId) throws FileNotFoundException {
        deleteDocument(documentId);
    }

    private static void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (!Files.isSymbolicLink(f.toPath())) {
                        deleteRecursive(f);
                    }
                }
            }
        }

        file.delete();
    }


    private static String getMimeType(String url) {
        String type = null;
        String extension = MimeTypeMap.getFileExtensionFromUrl(url.toLowerCase());

        if (extension != null) {
            switch (extension) {
                case "pbm":
                    type = "image/bmp";
                    break;
                case "yml":
                    type = "text/x-yaml";
                    break;
                default:
                    type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
                    break;
            }
        }

        if (type == null) {
            type = "application/octet-stream";
        }

        return type;
    }

    private void pushFile(MatrixCursor result, File file) throws FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException("Couldn't find file: " + file.getAbsolutePath());
        }

        String mimeType = "application/octet-stream";
        int flags = 0;

        if (file.isDirectory()) {
            mimeType = Document.MIME_TYPE_DIR;

            if (file.canWrite()) {
                flags |= Document.FLAG_DIR_SUPPORTS_CREATE;
            }
        } else if (file.isFile()) {
            mimeType = getMimeType(file.getAbsolutePath());

            if (file.canWrite()) {
                flags |= Document.FLAG_SUPPORTS_WRITE;
            }
        }

        if (file.getParentFile().canWrite()) {
            flags |= Document.FLAG_SUPPORTS_DELETE | Document.FLAG_SUPPORTS_RENAME;
        }

        RowBuilder row = result.newRow();
        row.add(Document.COLUMN_DOCUMENT_ID, file.getAbsolutePath());
        row.add(Document.COLUMN_DISPLAY_NAME, file.getName());
        row.add(Document.COLUMN_SIZE, file.length());
        row.add(Document.COLUMN_LAST_MODIFIED, file.lastModified());
        row.add(Document.COLUMN_FLAGS, flags);
        row.add(Document.COLUMN_MIME_TYPE, mimeType);
        row.add(Document.COLUMN_ICON, R.mipmap.ic_launcher);
    }
}

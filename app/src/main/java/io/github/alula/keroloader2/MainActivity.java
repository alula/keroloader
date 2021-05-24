package io.github.alula.keroloader2;

import android.app.NativeActivity;
import android.content.res.Configuration;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Bundle;
import android.view.OrientationEventListener;
import android.view.WindowInsets;

import static android.os.Build.VERSION.SDK_INT;

public class MainActivity extends NativeActivity {
    private int[] displayInsets = new int[]{0, 0, 0, 0};
    private OrientationEventListener listener;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        listener = new OrientationEventListener(this, SensorManager.SENSOR_DELAY_UI) {
            @Override
            public void onOrientationChanged(int orientation) {
                MainActivity.this.updateCutouts();
            }
        };

        if (listener.canDetectOrientation()) {
            listener.enable();
        } else {
            listener = null;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (listener != null) {
            listener.disable();

            listener = null;
        }
    }

    @Override
    public void onAttachedToWindow() {
        super.onAttachedToWindow();

        this.updateCutouts();
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);

        this.updateCutouts();
    }

    private void updateCutouts() {
        this.displayInsets[0] = 0;
        this.displayInsets[1] = 0;
        this.displayInsets[2] = 0;
        this.displayInsets[3] = 0;

        WindowInsets insets = getWindow().getDecorView().getRootWindowInsets();

        if (insets != null) {
            this.displayInsets[0] = Math.max(this.displayInsets[0], insets.getStableInsetLeft());
            this.displayInsets[1] = Math.max(this.displayInsets[1], insets.getStableInsetTop());
            this.displayInsets[2] = Math.max(this.displayInsets[2], insets.getStableInsetRight());
            this.displayInsets[3] = Math.max(this.displayInsets[3], insets.getStableInsetBottom());
        }

        if (SDK_INT >= Build.VERSION_CODES.P) {
            android.view.DisplayCutout cutout = insets.getDisplayCutout();

            if (cutout != null) {
                this.displayInsets[0] = Math.max(this.displayInsets[0], cutout.getSafeInsetLeft());
                this.displayInsets[1] = Math.max(this.displayInsets[0], cutout.getSafeInsetTop());
                this.displayInsets[2] = Math.max(this.displayInsets[0], cutout.getSafeInsetRight());
                this.displayInsets[3] = Math.max(this.displayInsets[0], cutout.getSafeInsetBottom());
            }

        }
    }
}
